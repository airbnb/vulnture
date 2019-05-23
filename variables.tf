data "aws_region" "current" {}

locals {
  # Set this to your 12-digit AWS account ID
  aws_account_id = "012345678901"
}

locals {
  lambda_function_name = "vulnture"
}

locals {
  # Set this to the AWS Secrets Manager secret name where you stored the SMTP password
  secret_name = "${local.lambda_function_name}/email-password"
  secret_arn  = "arn:aws:secretsmanager:${data.aws_region.current.name}:${local.aws_account_id}:secret:${local.secret_name}-*"
}

locals {
  dynamodb_table_name         = "Asset_Database"
  dynamodb_vendor_column_key  = "Vendor"
  dynamodb_product_column_key = "Product"
  verbosity_level             = 4
}

# Verbosity levels
# https://docs.python.org/3.7/library/logging.html#logging-levels
# 0 = nothing
# 1 = critical
# 2 = error, critical
# 3 = warning, error, critical
# 4 = info, warning, error, critical
# 5+ = debug, info, warning, error, critical

