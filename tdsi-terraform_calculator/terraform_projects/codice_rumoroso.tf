
provider "aws" {
  region = "eu-central-1"
}

variable "unused_admin_email" {
  type    = string
  default = "admin@example.com"
}


variable "env" {
  type    = string
  default = "dev"
}

resource "aws_vpc" "main_vpc" {
  # Debito: Valore "Magic String" hardcodato. Se volessimo cambiarlo, dovremmo cercarlo qui.
  cidr_block       = "10.10.0.0/16"
  
   instance_tenancy = "default"
  
  tags = {
    Name = "main_vpc_for_${var.env}"
  }
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.main_vpc.id
  # Debito: Un altro "Magic String" hardcodato.
  cidr_block              = "10.10.1.0/24"
  map_public_ip_on_launch = true

  tags = {
    Name = "Public Subnet"
  }
}

resource "aws_security_group" "web_sg" {
  name        = "web-server-sg"
  description = "Allow HTTP traffic"
  vpc_id      = aws_vpc.main_vpc.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web_server_1" {
  # Debito: Valore hardcodato per l'AMI. Se l'AMI cambia, dobbiamo aggiornarlo a mano ovunque.
  ami           = "ami-0a1ee2fb28fe35548" # Amazon Linux 2 in eu-central-1
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.web_sg.id]

   tags = {
    Name = "web_server_1"
    Role = "WebServer"
  }
}

resource "aws_instance" "web_server_2" {
  # Tutto questo blocco è una copia quasi carbone del precedente.
  ami           = "ami-0a1ee2fb28fe35548" 
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.web_sg.id]

  tags = {
    Name = "web-server-2" # Naming diverso
    Role = "WebServer"
  }
}

output "vpc_id" {
  value = aws_vpc.main_vpc.id
}