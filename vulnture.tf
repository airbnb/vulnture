data "archive_file" "vulnture_code" {
  type        = "zip"
  source_dir  = "code"
  output_path = "${local.lambda_function_name}.zip"
}

resource "aws_lambda_function" "vulnture_lambda_function" {
  description      = "vulnture - the open source, relevant security vulnerability notifier"
  function_name    = "${local.lambda_function_name}"
  role             = "${aws_iam_role.vulnture_iam_role.arn}"
  handler          = "main.handler"
  filename         = "${data.archive_file.vulnture_code.output_path}"
  source_code_hash = "${base64sha256(file(data.archive_file.vulnture_code.output_path))}"
  runtime          = "python3.7"
  timeout          = 300
  memory_size      = 1536
  publish          = true

  environment {
    variables = {
      EMAIL_PASSWORD_LOCATION = "${local.secret_name}"
    }
  }
}

resource "aws_cloudwatch_log_group" "vulnture_cloudwatch_log_group" {
  name              = "/aws/lambda/${local.lambda_function_name}"
  retention_in_days = 180
}

resource "aws_cloudwatch_event_rule" "run_daily_cloudwatch_event_rule" {
  name                = "${local.lambda_function_name}"
  description         = "CloudWatch Event triggered once per day to trigger vulnture."
  schedule_expression = "rate(1 day)"
}

resource "aws_cloudwatch_event_target" "lambda_cloudwatch_event_target" {
  rule = "${aws_cloudwatch_event_rule.run_daily_cloudwatch_event_rule.name}"
  arn  = "${aws_lambda_function.vulnture_lambda_function.arn}"

  input = <<EOF
  {
    "table_name": "${local.dynamodb_table_name}",
    "vendor_key": "${local.dynamodb_vendor_column_key}",
    "product_key": "${local.dynamodb_product_column_key}",
    "verbosity": ${local.verbosity_level}
  }
  EOF
}

resource "aws_lambda_permission" "lambda_permission" {
  statement_id  = "AllowExecutionFromCloudWatchEvents"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.vulnture_lambda_function.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.run_daily_cloudwatch_event_rule.arn}"
}

data "aws_iam_policy_document" "lambda_trust_iam_policy_document" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "vulnture_iam_role" {
  name               = "${local.lambda_function_name}"
  description        = "IAM role to be assumed by Lambda function ${local.lambda_function_name}."
  assume_role_policy = "${data.aws_iam_policy_document.lambda_trust_iam_policy_document.json}"
}

data "aws_iam_policy_document" "lambda_permissions_iam_policy_document" {
  statement {
    sid = "SecretsManagerGetSecretValueDynamoDBScan"

    actions = [
      "secretsmanager:GetSecretValue",
      "dynamodb:Scan",
    ]

    resources = [
      "${aws_dynamodb_table.dynamodb_table.arn}",
      "${local.secret_arn}",
    ]
  }
}

resource "aws_iam_role_policy" "lambda_permissions_iam_role_policy" {
  name   = "step-function-start-execution-policy"
  role   = "${aws_iam_role.vulnture_iam_role.name}"
  policy = "${data.aws_iam_policy_document.lambda_permissions_iam_policy_document.json}"
}

data "aws_iam_policy" "aws_managed_lambda_basic_execution_iam_policy" {
  arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "vulnture_iam_role_policy_attachment" {
  role       = "${aws_iam_role.vulnture_iam_role.name}"
  policy_arn = "${data.aws_iam_policy.aws_managed_lambda_basic_execution_iam_policy.arn}"
}

resource "aws_dynamodb_table" "dynamodb_table" {
  name           = "${local.dynamodb_table_name}"
  hash_key       = "Product"
  read_capacity  = 1
  write_capacity = 1

  server_side_encryption {
    enabled = true
  }

  attribute = {
    name = "Product"
    type = "S"
  }
}
