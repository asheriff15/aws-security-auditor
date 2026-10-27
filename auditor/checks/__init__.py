from auditor.checks import ec2, iam, s3

REGISTRY = {"s3": s3.run, "iam": iam.run, "ec2": ec2.run}
