Questa sezione è per chiunque voglia semplicemente usare il tool.

### Prerequisiti

Per utilizzare questo tool, sono necessari solo due programmi:

1. **Git** - Per scaricare il progetto.
    
2. **Docker Desktop** - Per eseguire il tool. Assicurati che sia installato e **in esecuzione** (l'icona della balena deve essere visibile e stabile).
    

### Istruzioni

Segui questi semplici passaggi dal tuo terminale preferito (PowerShell, CMD, Bash, etc.):

**1. Scarica il Progetto**  
Clona questo repository sulla tua macchina. https://github.com/NuclearOX/TDSI.git

codeBash

```
git clone <https://github.com/NuclearOX/TDSI.git>
```

**2. Entra nella Cartella del Progetto**

codeBash

```
cd tdsi_terraform_calculator/terraform_projects
```

**3. Costruisci l'Immagine Docker**  
Questo comando legge il Dockerfile e crea un'immagine locale del tool. Devi farlo solo la prima volta o ogni volta che il codice viene aggiornato.

codeBash

```
docker build -t qds-tool .
```

**4. Esegui il Tool**  
Questo comando avvia il container. Il container eseguirà l'analisi, mostrerà i risultati a schermo e poi si auto-eliminerà per non lasciare spazzatura (--rm).

codeBash

```
docker run --rm qds-tool
```

L'output mostrerà il dettaglio dei problemi trovati e il punteggio QDS finale.