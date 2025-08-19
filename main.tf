locals {
  resource_tags = merge(var.tags, { "Automation" = "Terraform" })
  alarm_prefix  = var.alarm_prefix != "" ? "${var.alarm_prefix}-" : ""
}

resource "aws_cloudwatch_log_metric_filter" "unauthorized_api_calls" {
  count = var.unauthorized_api_calls ? 1 : 0

  name           = "UnauthorizedAPICalls"
  pattern        = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "UnauthorizedAPICalls"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api_calls" {
  count = var.unauthorized_api_calls ? 1 : 0

  alarm_name                = "${local.alarm_prefix}UnauthorizedAPICalls"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.unauthorized_api_calls[0].id
  namespace                 = var.alarm_namespace
  period                    = "60"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = var.enable_alarm_descriptions ? "Monitoring unauthorized API calls will help reveal application errors and may reduce time to detect malicious activity." : null
  alarm_actions             = [var.alarm_sns_topic_arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = local.resource_tags
}

resource "aws_cloudwatch_log_metric_filter" "no_mfa_console_signin_assumed_role" {
  count = var.no_mfa_console_login && !var.disable_assumed_role_login_alerts ? 1 : 0

  name           = "NoMFAConsoleSignin"
  pattern        = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") }"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "NoMFAConsoleSignin"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "no_mfa_console_signin_no_assumed_role" {
  count = var.no_mfa_console_login && var.disable_assumed_role_login_alerts ? 1 : 0

  name           = "NoMFAConsoleSignin"
  pattern        = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") && ($.userIdentity.arn != \"*assumed-role*\") }"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "NoMFAConsoleSignin"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "no_mfa_console_signin" {
  count = var.no_mfa_console_login ? 1 : 0

  alarm_name                = "${local.alarm_prefix}NoMFAConsoleSignin"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = var.disable_assumed_role_login_alerts ? aws_cloudwatch_log_metric_filter.no_mfa_console_signin_no_assumed_role[0].id : aws_cloudwatch_log_metric_filter.no_mfa_console_signin_assumed_role[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = var.enable_alarm_descriptions ? "Monitoring for single-factor console logins will increase visibility into accounts that are not protected by MFA." : null
  alarm_actions             = [var.alarm_sns_topic_arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = local.resource_tags
}

resource "aws_cloudwatch_log_metric_filter" "root_usage" {
  count = var.root_usage ? 1 : 0

  name           = "RootUsage"
  pattern        = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "RootUsage"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_usage" {
  count = var.root_usage ? 1 : 0

  alarm_name                = "${local.alarm_prefix}RootUsage"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.root_usage[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = var.enable_alarm_descriptions ? "Monitoring for root account logins will provide visibility into the use of a fully privileged account and an opportunity to reduce the use of it." : null
  alarm_actions             = [var.alarm_sns_topic_arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = local.resource_tags
}

resource "aws_cloudwatch_log_metric_filter" "iam_changes" {
  count = var.iam_changes ? 1 : 0

  name           = "IamPolicyChange"
  pattern        = "{($.eventSource=iam.amazonaws.com) && (($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy))}"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "IamPolicyChange"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam_changes" {
  count = var.iam_changes ? 1 : 0

  alarm_name                = "${local.alarm_prefix}IamPolicyChange"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.iam_changes[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = var.enable_alarm_descriptions ? "Monitoring changes to IAM policies will help ensure authentication and authorization controls remain intact." : null
  alarm_actions             = [var.alarm_sns_topic_arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = local.resource_tags
}

resource "aws_cloudwatch_log_metric_filter" "cloudtrail_cfg_changes" {
  count = var.cloudtrail_cfg_changes ? 1 : 0

  name           = "CloudTrailConfigChange"
  pattern        = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "CloudTrailConfigChange"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cloudtrail_cfg_changes" {
  count = var.cloudtrail_cfg_changes ? 1 : 0

  alarm_name                = "${local.alarm_prefix}CloudTrailConfigChange"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.cloudtrail_cfg_changes[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = var.enable_alarm_descriptions ? "Monitoring changes to CloudTrail's configuration will help ensure sustained visibility to activities performed in the AWS account." : null
  alarm_actions             = [var.alarm_sns_topic_arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = local.resource_tags
}

resource "aws_cloudwatch_log_metric_filter" "console_signin_failures" {
  count = var.console_signin_failures ? 1 : 0

  name           = "SignInFailures"
  pattern        = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "SignInFailures"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "console_signin_failures" {
  count = var.console_signin_failures ? 1 : 0

  alarm_name                = "${local.alarm_prefix}SignInFailures"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.console_signin_failures[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = var.enable_alarm_descriptions ? "Monitoring failed console logins may decrease lead time to detect an attempt to brute force a credential, which may provide an indicator, such as source IP, that can be used in other event correlation." : null
  alarm_actions             = [var.alarm_sns_topic_arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = local.resource_tags
}

resource "aws_cloudwatch_log_metric_filter" "disable_or_delete_cmk" {
  count = var.disable_or_delete_cmk ? 1 : 0

  name           = "CMKDisabledOrScheduledDeleted"
  pattern        = "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "CMKDisabledOrScheduledDeleted"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "disable_or_delete_cmk" {
  count = var.disable_or_delete_cmk ? 1 : 0

  alarm_name                = "${local.alarm_prefix}CMKDisabledOrScheduledDeleted"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.disable_or_delete_cmk[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = var.enable_alarm_descriptions ? "Data encrypted with disabled or deleted keys will no longer be accessible." : null
  alarm_actions             = [var.alarm_sns_topic_arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = local.resource_tags
}

resource "aws_cloudwatch_log_metric_filter" "s3_bucket_policy_changes" {
  count = var.s3_bucket_policy_changes ? 1 : 0

  name           = "S3BucketPolicyChange"
  pattern        = "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "S3BucketPolicyChange"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "s3_bucket_policy_changes" {
  count = var.s3_bucket_policy_changes ? 1 : 0

  alarm_name                = "${local.alarm_prefix}S3BucketPolicyChange"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.s3_bucket_policy_changes[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = var.enable_alarm_descriptions ? "Monitoring changes to S3 bucket policies may reduce time to detect and correct permissive policies on sensitive S3 buckets." : null
  alarm_actions             = [var.alarm_sns_topic_arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = local.resource_tags
}

resource "aws_cloudwatch_log_metric_filter" "aws_config_changes" {
  count = var.aws_config_changes ? 1 : 0

  name           = "AwsConfigConfigurationChange"
  pattern        = "{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "AwsConfigConfigurationChange"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "aws_config_changes" {
  count = var.aws_config_changes ? 1 : 0

  alarm_name                = "${local.alarm_prefix}AwsConfigConfigurationChange"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.aws_config_changes[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = var.enable_alarm_descriptions ? "Monitoring changes to AWS Config configuration will help ensure sustained visibility of configuration items within the AWS account." : null
  alarm_actions             = [var.alarm_sns_topic_arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = local.resource_tags
}

resource "aws_cloudwatch_log_metric_filter" "security_group_changes" {
  count = var.security_group_changes ? 1 : 0

  name           = "SecurityGroupChanges"
  pattern        = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup)}"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "SecurityGroupChanges"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "security_group_changes" {
  count = var.security_group_changes ? 1 : 0

  alarm_name                = "${local.alarm_prefix}SecurityGroupChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.security_group_changes[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = var.enable_alarm_descriptions ? "Monitoring changes to security group will help ensure that resources and services are not unintentionally exposed." : null
  alarm_actions             = [var.alarm_sns_topic_arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = local.resource_tags
}

resource "aws_cloudwatch_log_metric_filter" "nacl_changes" {
  count = var.nacl_changes ? 1 : 0

  name           = "NACLChanges"
  pattern        = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "NACLChanges"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "nacl_changes" {
  count = var.nacl_changes ? 1 : 0

  alarm_name                = "${local.alarm_prefix}NACLChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.nacl_changes[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = var.enable_alarm_descriptions ? "Monitoring changes to NACLs will help ensure that AWS resources and services are not unintentionally exposed." : null
  alarm_actions             = [var.alarm_sns_topic_arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = local.resource_tags
}

resource "aws_cloudwatch_log_metric_filter" "network_gw_changes" {
  count = var.network_gw_changes ? 1 : 0

  name           = "NetworkGatewayChange"
  pattern        = "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "NetworkGatewayChange"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "network_gw_changes" {
  count = var.network_gw_changes ? 1 : 0

  alarm_name                = "${local.alarm_prefix}NetworkGatewayChange"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.network_gw_changes[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = var.enable_alarm_descriptions ? "Monitoring changes to network gateways will help ensure that all ingress/egress traffic traverses the VPC border via a controlled path." : null
  alarm_actions             = [var.alarm_sns_topic_arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = local.resource_tags
}

resource "aws_cloudwatch_log_metric_filter" "route_table_changes" {
  count = var.route_table_changes ? 1 : 0

  name           = "RouteTableChange"
  pattern        = "{($.eventSource=ec2.amazonaws.com) && (($.eventName=CreateRoute) || ($.eventName=CreateRouteTable) || ($.eventName=ReplaceRoute) || ($.eventName=ReplaceRouteTableAssociation) || ($.eventName=DeleteRouteTable) || ($.eventName=DeleteRoute) || ($.eventName=DisassociateRouteTable))}"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "RouteTableChange"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "route_table_changes" {
  count = var.route_table_changes ? 1 : 0

  alarm_name                = "${local.alarm_prefix}RouteTableChange"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.route_table_changes[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = var.enable_alarm_descriptions ? "Monitoring changes to route tables will help ensure that all VPC traffic flows through an expected path." : null
  alarm_actions             = [var.alarm_sns_topic_arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = local.resource_tags
}

resource "aws_cloudwatch_log_metric_filter" "vpc_changes" {
  count = var.vpc_changes ? 1 : 0

  name           = "VPCChange"
  pattern        = "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "VPCChange"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "vpc_changes" {
  count = var.vpc_changes ? 1 : 0

  alarm_name                = "${local.alarm_prefix}VPCChange"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.vpc_changes[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = var.enable_alarm_descriptions ? "Monitoring changes to VPC will help ensure that all VPC traffic flows through an expected path." : null
  alarm_actions             = [var.alarm_sns_topic_arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = local.resource_tags
}
