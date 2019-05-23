# For additional configuration options see https://www.terraform.io/docs/providers/aws/index.html
provider "aws" {
  # vulnture infrastructure will be deployed in this region
  region = "us-east-1"

  # AWS named profile - https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html
  profile = "my_aws_profile"
}
