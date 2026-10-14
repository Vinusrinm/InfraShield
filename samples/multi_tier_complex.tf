# Complete Multi-Tier Infrastructure Configuration
# Includes: Network, Security Group, Server, S3 Storage, and Database

resource "aws_vpc" "production_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  tags = {
    Name = "infrashield-prod-vpc"
  }
}

resource "aws_security_group" "web_sg" {
  name        = "web-tier-sg"
  vpc_id      = aws_vpc.production_vpc.id
  description = "Web tier firewall"

  ingress {
    description = "SSH from anywhere - VULNERABLE"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Public Web Traffic"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web_server" {
  ami                    = "ami-0c55b159cbfafe1f0"
  instance_type          = "t3.medium"
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  tags = {
    Name = "web-tier-instance"
  }
}

resource "aws_s3_bucket" "data_archive" {
  bucket = "infrashield-finance-backups"
  acl    = "public-read" # Vulnerable public storage
}

resource "aws_db_instance" "primary_db" {
  allocated_storage   = 50
  engine              = "postgres"
  engine_version      = "15.3"
  instance_class      = "db.t3.medium"
  db_name             = "production_db"
  storage_encrypted   = true
  publicly_accessible = false
  skip_final_snapshot = true
}
