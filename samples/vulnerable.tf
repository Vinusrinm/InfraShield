# Vulnerable Terraform Configuration for Demo / Hackathon
# WARNING: This configuration contains intentional security violations for scanning demonstrations.

terraform {
  required_version = ">= 1.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# Policy Violation 1: CKV_AWS_24 / CKV_AWS_23 - Public SSH Exposure (CRITICAL)
# Exposes port 22 to 0.0.0.0/0 (the entire internet), allowing brute force attacks.
resource "aws_security_group" "web_sg" {
  name        = "demo-security-group"
  description = "Web tier security group with internet-facing rules"
  vpc_id      = "vpc-0123456789abcdef0"

  ingress {
    description = "Unrestricted administrative SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Public HTTP web traffic"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Outbound traffic to internet"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
    Project     = "InfraShield-Demo"
  }
}

# Associated Web Server Instance
resource "aws_instance" "web_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  vpc_security_group_ids = [
    aws_security_group.web_sg.id
  ]

  tags = {
    Name        = "infrashield-web-server"
    Role        = "frontend-app"
    Environment = "production"
  }
}
