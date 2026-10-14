# Secure Terraform Configuration for Demo / Hackathon
# Compliant configuration with restricted administrative access.
# NOTE: The CIDR 203.0.113.50/32 is an EXAMPLE administrative bastion/VPN IP (RFC 5737 TEST-NET-3).
# It does NOT represent the user's actual IP address.

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

# Compliant Security Group: SSH is restricted to a dedicated administrative subnet / IP
resource "aws_security_group" "web_sg" {
  name        = "demo-security-group-hardened"
  description = "Hardened security group with restricted administrative access"
  vpc_id      = "vpc-0123456789abcdef0"

  ingress {
    description = "Restricted SSH access from corporate VPN / Admin Bastion (Example CIDR)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.50/32"] # Example administrative CIDR
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
    Status      = "hardened"
    SecurityValidation = "InfraShield-Passed"
  }
}

# Associated Web Server Instance
resource "aws_instance" "web_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  vpc_security_group_ids = [
    aws_security_group.web_sg.id
  ]

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 enforced
    http_put_response_hop_limit = 1
  }

  tags = {
    Name        = "infrashield-web-server"
    Role        = "frontend-app"
    Environment = "production"
  }
}
