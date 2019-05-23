# vulnture
**vulnture** is a serverless tool that allows you and/or your organization to quickly and easily seek out *relevant* security vulnerabilities.

## Overview
The purpose of **vulnture** is to automate the discovery of security vulnerabilities relevant to you and/or your organization. Any hardware and/or software produced by any vendor is supported! All that is required in order for **vulnture** to effectively find the desired vendor and product is properly spelled and formatted names, as required by the vulnerability source(s) being searched.

**vulnture** runs once daily and seeks all vulnerabilities created or modified the previous day. The intent here is to ensure that no vulnerabilities are missed. If **vulnture** were to seek out relevant vulnerabilities freshly reported that day and only run once daily, it's plausible that additional vulnerabilities could appear later on in the day and then would never be seen. Multiple runs in a single day would yield duplicates since **vulnture** does not track state (yet).

## Quick Start

---

### Prerequisites
- Have credentials for a SMTP user (e.g. email and password) that will be used to send notification emails handy
- Store the SMTP user password in [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/) within the AWS account you will be deploying **vulnture**

---

1. Download the code

    ```sh
    git clone https://github.com/airbnb/vulnture.git
    cd vulnture
    ```

2. Update the [configuration file](code/project/conf/conf.ini) to desired configuration (at a minimum, update `EmailRecipients` and `SMTPSender`)

3. Update the `provider` block within [providers.tf](providers.tf) to make use of your own named profile or AWS credentials

4. Update the values for `aws_account_id` and `secret_name` within [variables.tf](variables.tf)

5. Deploy the infrastructure via [Terraform](https://www.terraform.io/)

    ```sh
    terraform init
    terraform apply
    ```

    **NOTE**: No [Terraform backend](https://www.terraform.io/docs/backends/index.html) is configured, so the "local" backend is used by default - you may want to consider configuring a backend that maintains Terraform state elsewhere

6. In the DynamoDB table created for you in Step 4 (named *Asset_Database* by default), add items representing the assets for which you'd like vulnerability alerts. Only two columns/attributes are required, `Vendor` and `Product`, though more can be added without issue (**vulnture** won't use them for anything at the moment).

    For examples of vendors and products to add, you may wish to download a recent [NVD data feed](https://nvd.nist.gov/vuln/data-feeds) and search for `vendor_name` and `product_name`. Note that **vulnture** replaces spaces in product names with underscores when searching NVD feeds, so you don't need to use underscores when entering products into your asset database.

## How It Works
**vulnture** searches various sources of security vulnerability announcements, those enabled via the configuration file, for vulnerabilities associated with relevant products. Relevant products in this context means any products found within the asset database that **vulnture** is configured to use. All configuration is done in a single configuration file.

By default, **vulnture** uses a table within [AWS DynamoDB](https://aws.amazon.com/dynamodb/) as its asset database. The asset database enables the search for relevant products to be performed.

The high-level overview of how **vulnture** works is outlined below:

1. Get a list of all vendors and products from the asset database (a DynamoDB table by default)
2. Search the configured vulnerability feed(s) for vulnerabilities associated with any asset within the asset database
3. Notify configured recipients (email by default) key details from each relevant vulnerability, if any found

![Vulnerability Notification System Architecture Diagram](docs/vulnture%20architecture%20diagram.png)

## Low-Level Details
If you're curious in drilling down further into the technical details each of the steps mentioned above, read on.

#### Step 1 (Get list of vendors & products from asset database)
- Scan (read all) items from DynamoDB table acting as the asset database
- Create Asset objects containing vendor and product names, and potentially search keywords, then store them all in a set
    - Keywords are generated via a `get_keywords()` function, only if regular expressions and other details are provided in [product_patterns.py](code/project/plugins/assets/product_patterns.py), otherwise the "keywords" are merely the product name - keywords are intended to be used in cases where your asset product names are actually model numbers that need to be translated to product names

#### Step 2 (Search vulnerability feeds for vulnerabilities associated with products from asset database)
- Iterate through each asset in the set created in Step 1 and, for each enabled vulnerability feed, search for vulnerabilities associated with the asset then store discovered relevant vulnerabilities in a set

#### Step 3 (Send vulnerability notifications)
- Iterate through each vulnerability in the set created in Step 2, if any, and format the key details then send out notifications (email by default) to configured recipients
    - The default email notification uses a helper module, [send_email.py](code/project/modules/send_email.py), to send emails to the recipient(s) set within the configuration file with subject *vulnture - relevant vulnerabilities detected!* via SMTP over SSL using a STMP server of your choice (Gmail™ by default) using a password stored in AWS Secrets Manager - you must store the password manually and then update the appropriate local variable in [variables.tf](variables.tf)

## Things To Note
- Currently, the tool only supports a single asset database, though supporting multiple asset databases is being considered as a future feature.
- The tool does not currently maintain state of any kind. If one or more relevant vulnerabilities are detected at some point in time, and then the same vulnerabilities are detected by the tool at a later date, they will be sent via configured notification(s) again.
    - Future plans involve tracking state of assets and vulnerabilities to prevent this, as well as track metrics such as time to time to resolution, number of vulnerabilities reported by vendor or product, etc.
- Logging is enabled by default in most, but not all modules of this project. In all modules where logging is enabled, the [root logger](https://docs.python.org/3/library/logging.html#logging.getLogger) is used. Because of this, some modules used by **vulnture** that also make use of the [logging module](https://docs.python.org/3/library/logging.html) may display log messages alongside **vulnture** log messages.
- **vulnture** is still in active development! Some code and features are incomplete, with changes/updates planned in the near future, but this does not hinder the base functionality of **vulnture**! A stable deployment of **vulnture** has run successfully for several months.
- Please open a [GitHub issue](https://github.com/airbnb/vulnture/issues) if you encounter any bugs, errors, or would like to submit a feature request! Additionally, feel free to contribute by opening PRs!

## Testing Locally
If you'd like to test the output of **vulnture** on your own machine after getting the code, simply navigate to the `code` directory and then execute `main.py` with the `--test` argument

```sh
git clone https://github.com/airbnb/vulnture.git
cd vulnture/code
python3 main.py --test -vvvvv
```

In this example, the `-vvvvv` argument is optional and is simply used to set verbosity to the highest level. Each `v` in this option represents an additional level of logging verbosity. Verbosity levels range from 0-5, from no logging to full logging (all severity levels). Verbosity levels are briefly described in [variables.tf](variables.tf) within the comments.

In testing mode the user is prompted for input. Specifically, the user is asked to enter:
- vendor name
- product name
- keyword (optional)

Only a single entry can be added for each of these three inputs, so at the moment testing is only useful for testing a single asset at a time.

## Trademark Attribution
All trademarks are the property of their registered owners; Airbnb claims no responsibility for nor proprietary interest in them.

Amazon Web Services, the “Powered by AWS” logo, AWS, AWS Lambda, and DynamoDB are trademarks of Amazon.com, Inc. or its affiliates in the United States and/or other countries.

Cisco is a registered trademark or trademark of Cisco Systems, Inc. and/or its affiliates in the United States and certain other countries.

Gmail email service is a trademark of Google LLC.
