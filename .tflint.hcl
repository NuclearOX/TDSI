plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

# AWS Ruleset
plugin "aws" {
    enabled = true
    source  = "github.com/terraform-linters/tflint-ruleset-aws"
    version = "0.32.0" 
}

# Google Cloud Ruleset (Per gcp-k8s)
plugin "google" {
    enabled = true
    source  = "github.com/terraform-linters/tflint-ruleset-google"
    version = "0.29.0"
}

# Azure Ruleset (Per completezza)
plugin "azurerm" {
    enabled = true
    source  = "github.com/terraform-linters/tflint-ruleset-azurerm"
    version = "0.27.0"
}

config {
  module = true
  force = false
  disabled_by_default = false
}