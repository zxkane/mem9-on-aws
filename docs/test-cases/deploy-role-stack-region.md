# Deploy-role stack region test cases

## Scope

Verify that the out-of-band GitHub Actions IAM ownership stack always uses
`us-west-2`, while application VPC discovery follows `providers.aws.region` in
`sst.config.ts`. Tests execute the real shell wrapper against a fake AWS CLI and
perform no live AWS mutations.

## Cases

### TC-DEPLOY-ROLE-001: Ambient region cannot redirect auto-detection

- Set `AWS_REGION=us-east-2`.
- Model the existing ownership stack only in `us-west-2`.
- Run `scripts/deploy-github-role.sh` without a mode flag.
- Expect stack discovery to use `us-west-2` and select update mode.
- Expect every CloudFormation call to use `us-west-2`.

### TC-DEPLOY-ROLE-002: Forced create and update stay pinned

- Set `AWS_REGION=us-east-2`.
- Run the wrapper with `--create` and `--update` in separate fixtures.
- Expect create, update, wait, and output lookup calls to use `us-west-2`.

### TC-DEPLOY-ROLE-003: Application region remains independent

- Set the fixture `sst.config.ts` provider to `eu-west-1`.
- Set unrelated `AWS_REGION=us-east-2` and `PROJECT_REGION=us-east-1`.
- Run the wrapper against the fake AWS CLI.
- Expect EC2 VPC and subnet discovery to use `eu-west-1`.
- Expect the CloudFormation `ApplicationRegion` parameter to be `eu-west-1`.
- Expect all CloudFormation stack operations to remain in `us-west-2`.

### TC-DEPLOY-ROLE-004: Existing live region cannot be retargeted in place

- Set the fixture `sst.config.ts` provider to `eu-west-1`.
- Model an existing ownership stack whose `ApplicationRegion` is
  `ap-northeast-1`.
- Run the wrapper with `--update`.
- Expect failure before `UpdateStack`; live relocation requires a separately
  reviewed dual-region migration after old-region previews are removed.
