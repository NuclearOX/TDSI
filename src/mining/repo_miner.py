from pydriller import Repository
from src.metrics.quality_model import QualityAnalyzer
from src.metrics.security_model import SecurityAnalyzer
from src import config
import logging
import os
import shutil
import tempfile
import subprocess

logger = logging.getLogger(__name__)

class RepoMiner:
    def __init__(self, repo_url: str, repo_name: str):
        self.repo_url = repo_url
        self.repo_name = repo_name

    def mine_history(self):
        """
        Strategia Adattiva Ottimizzata:
        1. Clona il repo UNA volta sola.
        2. Prova a cercare TAG.
        3. Se non trova nulla, sullo STESSO clone, cerca i COMMIT.
        4. Pulisce tutto.
        """
        logger.info(f"Inizio mining di: {self.repo_name}")
        
        # Creiamo una directory temporanea unica per questo repo
        temp_dir = tempfile.mkdtemp()
        clone_path = os.path.join(temp_dir, self.repo_name)
        
        try:
            # 1. CLONE MANUALE (Una volta sola)
            # Usiamo subprocess per avere controllo totale ed evitare errori di PyDriller sul clone
            logger.info(f"Cloning {self.repo_url} in {clone_path}...")
            subprocess.run(
                ["git", "clone", self.repo_url, clone_path], 
                check=True, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL
            )

            # 2. Tentativo 1: Analisi per TAG (Release)
            generator = self._get_commits_generator(clone_path, only_tags=True)
            
            found_tags = False
            count = 0
            
            # Proviamo a iterare. Se il generatore è vuoto, il loop non parte.
            for data_point in self._process_generator(generator, mode="TAG"):
                found_tags = True
                yield data_point
                count += 1
                if count >= config.MAX_SNAPSHOTS:
                    logger.info(f"Raggiunto limite di {config.MAX_SNAPSHOTS} TAG per {self.repo_name}.")
                    return # Esce e va al finally

            # 3. Tentativo 2: Fallback sui COMMIT (se non abbiamo trovato tag)
            if not found_tags:
                logger.info(f"Nessun tag trovato per {self.repo_name}. Passo alla modalità COMMIT (.tf only).")
                
                # Riutilizziamo lo stesso clone_path! Zero download aggiuntivi.
                generator = self._get_commits_generator(clone_path, only_tags=False)
                
                for data_point in self._process_generator(generator, mode="COMMIT"):
                    yield data_point
                    count += 1
                    if count >= config.MAX_SNAPSHOTS:
                        logger.info(f"Raggiunto limite di {config.MAX_SNAPSHOTS} COMMIT per {self.repo_name}.")
                        return

        except subprocess.CalledProcessError:
            logger.error(f"Impossibile clonare il repository {self.repo_url}")
        except Exception as e:
            logger.error(f"Errore critico nel mining di {self.repo_name}: {e}")
        finally:
            # 4. PULIZIA (Sempre, anche se ci sono errori)
            if os.path.exists(temp_dir):
                try:
                    # Su Windows a volte i file sono lockati, proviamo a forzare
                    shutil.rmtree(temp_dir, ignore_errors=True)
                except Exception as e:
                    logger.warning(f"Non sono riuscito a cancellare la temp dir {temp_dir}: {e}")

    def _get_commits_generator(self, path: str, only_tags: bool):
        """Configura PyDriller su un path locale."""
        return Repository(
            path_to_repo=path, # Usa path locale, non URL
            only_releases=only_tags,
            # Se cerchiamo commit, vogliamo solo quelli che toccano file .tf
            only_modifications_with_file_types=['.tf'] if not only_tags else None,
            order='reverse' # Dal più recente al più vecchio
        ).traverse_commits()

    def _process_generator(self, generator, mode: str):
        """Logica comune di analisi con filtro anti-duplicati e sanitizzazione CSV."""
        
        # Teniamo traccia delle metriche precedenti per la logica "Delta"
        last_metrics_hash = None

        for commit in generator:
            try:
                current_path = commit.project_path
                
                # 1. Analisi Qualità
                q_analyzer = QualityAnalyzer(current_path)
                q_metrics = q_analyzer.analyze()

                # Se non c'è codice Terraform (LOC=0), salta (es. commit di docs)
                if q_metrics['loc'] == 0:
                    continue

                # 2. Analisi Sicurezza
                s_analyzer = SecurityAnalyzer(current_path)
                s_metrics = s_analyzer.analyze()

                # --- LOGICA DELTA: Salviamo solo se i numeri cambiano ---
                # Creiamo una "impronta" delle metriche chiave
                current_metrics_hash = (
                    q_metrics['loc'], 
                    q_metrics['iac_mccabe_complexity'],
                    s_metrics['security_debt_score'],
                    s_metrics['critical_count']
                )

                # Se le metriche sono identiche all'ultimo snapshot salvato, saltiamo
                if current_metrics_hash == last_metrics_hash:
                    continue
                
                # Aggiorniamo l'ultimo hash visto
                last_metrics_hash = current_metrics_hash

                logger.info(f"  [{mode}] {commit.hash[:7]} | LOC: {q_metrics['loc']} | SecDebt: {s_metrics['security_debt_score']}")

                # --- SANITIZZAZIONE PER CSV ---
                # Puliamo il messaggio del tag/commit da virgole e a capo che rompono il CSV
                raw_tag_msg = commit.msg
                clean_tag = str(raw_tag_msg).replace('\n', ' ').replace('\r', '').replace(',', ' ').replace(';', ' ').strip()
                # Limitiamo la lunghezza del messaggio per evitare problemi
                clean_tag = clean_tag[:100]

                data_point = {
                    'repo_name': self.repo_name,
                    'git_url': self.repo_url,
                    'commit_hash': commit.hash,
                    'tag': clean_tag if mode == "TAG" else f"Commit: {clean_tag}",
                    'analysis_mode': mode,
                    'author_date': commit.author_date,
                    **q_metrics,
                    **s_metrics
                }
                
                yield data_point

            except Exception as e:
                logger.error(f"Errore commit {commit.hash}: {e}")
                continue