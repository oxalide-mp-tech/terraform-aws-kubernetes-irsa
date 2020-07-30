resource "aws_s3_bucket" "oidc" {
  bucket = var.oidc_s3_bucket_name
  acl    = "private"
}

resource "aws_s3_bucket_object" "oidc_discovery" {
  depends_on = [aws_s3_bucket.oidc]
  bucket     = var.oidc_s3_bucket_name
  key        = "/.well-known/openid-configuration"
  acl        = "public-read"
  content    = <<EOF
{
  "issuer": "https://${aws_s3_bucket.oidc.bucket_domain_name}/",
  "jwks_uri": "https://${aws_s3_bucket.oidc.bucket_domain_name}/jwks.json",
  "authorization_endpoint": "urn:kubernetes:programmatic_authorization",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256"
  ],
  "claims_supported": [
    "sub",
    "iss"
  ]
}
EOF
}

resource "aws_s3_bucket_object" "oidc_jwks" {
  depends_on = [aws_s3_bucket.oidc]
  bucket     = var.oidc_s3_bucket_name
  key        = "/jwks.json"
  acl        = "public-read"
  source     = var.oidc_jwks_filename
}

resource "aws_iam_openid_connect_provider" "irsa" {
  url             = "https://${aws_s3_bucket.oidc.bucket_domain_name}"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [var.oidc_ca_sha1]
}

resource "aws_ecr_repository" "pod_identity_webhook" {
  provider = aws.ecr
  name     = "eks/pod-identity-webhook"
}

data "aws_region" "current_ecr" {
  provider = aws.ecr
}

resource "aws_codebuild_project" "pod_identity_webhook" {
  provider     = aws.ecr
  name         = "pod-identity-webhook"
  description  = "Build https://github.com/aws/amazon-eks-pod-identity-webhook"
  service_role = aws_iam_role.codebuild_pod_identity_webhook.arn

  source {
    type      = "GITHUB"
    location  = "https://github.com/aws/amazon-eks-pod-identity-webhook.git"
    buildspec = <<EOF
version: 0.2
phases:
  pre_build:
    commands:
      - echo Logging in to Amazon ECR...
      - aws --version
      - $(aws ecr get-login --region $AWS_DEFAULT_REGION --no-include-email)
  build:
    commands:
      - echo $CODEBUILD_SOURCE_VERSION
      - IMAGE=${aws_ecr_repository.pod_identity_webhook.registry_id}.dkr.ecr.${data.aws_region.current_ecr.name}.amazonaws.com/${aws_ecr_repository.pod_identity_webhook.name}
      - echo 'Building image $IMAGE...'
      - docker build --cache-from=$IMAGE -t $IMAGE .
      - docker tag $IMAGE $IMAGE:$CODEBUILD_SOURCE_VERSION
  post_build:
    commands:
      - echo Build completed on `date`
      - echo Pushing the Docker images...
      - docker push $IMAGE:latest
      - docker push $IMAGE:$CODEBUILD_SOURCE_VERSION
EOF
  }

  environment {
    compute_type    = "BUILD_GENERAL1_SMALL"
    image           = "aws/codebuild/amazonlinux2-x86_64-standard:3.0"
    type            = "LINUX_CONTAINER"
    privileged_mode = true # for docker build
  }

  artifacts {
    type = "NO_ARTIFACTS"
  }
}

resource "aws_iam_role" "codebuild_pod_identity_webhook" {
  provider           = aws.ecr
  name               = "codebuild_pod_identity_webhook"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "codebuild.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

# TODO: allow cross-account policy
resource "aws_iam_role_policy" "codebuild_pod_identity_webhook" {
  provider = aws.ecr
  role     = aws_iam_role.codebuild_pod_identity_webhook.name
  policy   = <<EOF
{
  "Version":"2012-10-17",
  "Statement": [
    {
      "Sid": "CloudWatchLogsPolicy",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": [
        "*"
      ]
    },
    {
      "Sid":"ListImagesInRepository",
      "Effect":"Allow",
      "Action":[
        "ecr:ListImages"
      ],
      "Resource":"${aws_ecr_repository.pod_identity_webhook.arn}"
    },
    {
      "Sid":"GetAuthorizationToken",
      "Effect":"Allow",
      "Action":[
        "ecr:GetAuthorizationToken"
      ],
      "Resource":"*"
    },
    {
      "Sid":"ManageRepositoryContents",
      "Effect":"Allow",
      "Action":[
            "ecr:GetAuthorizationToken",
            "ecr:BatchCheckLayerAvailability",
            "ecr:GetDownloadUrlForLayer",
            "ecr:GetRepositoryPolicy",
            "ecr:DescribeRepositories",
            "ecr:ListImages",
            "ecr:DescribeImages",
            "ecr:BatchGetImage",
            "ecr:InitiateLayerUpload",
            "ecr:UploadLayerPart",
            "ecr:CompleteLayerUpload",
            "ecr:PutImage"
      ],
      "Resource":"${aws_ecr_repository.pod_identity_webhook.arn}"
    }
  ]
}
EOF
}

resource "aws_ecr_repository_policy" "pod_identity_webhook" {
  provider   = aws.ecr
  repository = aws_ecr_repository.pod_identity_webhook.name

  policy = <<EOF
{
    "Version": "2008-10-17",
    "Statement": [
    {
      "Sid": "AllowPull",
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::283504130005:root",
          "arn:aws:iam::591830280611:root",
          "arn:aws:iam::848114327112:root",
          "arn:aws:iam::860996116171:root",
          "arn:aws:iam::660225450777:root",
          "arn:aws:iam::072369617205:root",
          "arn:aws:iam::908538848727:root",
          "arn:aws:iam::300377511235:root",
          "arn:aws:iam::311275790335:root"
        ]
      },
      "Action": [
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer"
      ]
    }
  ]
}
EOF
}

resource "aws_secretsmanager_secret" "irsa_keys_private" {
  name = "irsa_keys_private"
}

resource "aws_secretsmanager_secret_version" "irsa_keys_private" {
  secret_id     = aws_secretsmanager_secret.irsa_keys_private.id
  secret_string = file(var.signer_private_key_filename)
}


resource "aws_secretsmanager_secret" "irsa_keys_public" {
  name = "irsa_keys_public"
}

resource "aws_secretsmanager_secret_version" "irsa_keys_public" {
  secret_id     = aws_secretsmanager_secret.irsa_keys_public.id
  secret_string = file(var.signer_public_key_filename)
}
