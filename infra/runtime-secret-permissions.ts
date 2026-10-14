/** Exact parameter reads and decryption through SSM only. Reuse the existing
 * account/region's managed SSM key; no new key or runtime write permission. */
export function runtimeSsmSecretPermissions(arns: Input<string>[], region: Input<string>) {
  const key = aws.kms.getKeyOutput({ keyId: "alias/aws/ssm", region });
  return [
    { actions: ["ssm:GetParameters"], resources: arns },
    { actions: ["kms:Decrypt"], resources: [key.arn], conditions: [
      { test: "StringEquals", variable: "kms:ViaService", values: [$interpolate`ssm.${region}.amazonaws.com`] },
      { test: "ArnEquals", variable: "kms:EncryptionContext:PARAMETER_ARN", values: arns },
    ] },
  ];
}

/** The key ID comes from the existing owned Secret resource's provider output.
 * This neither chooses a new key nor changes secret contents/encryption. */
export function runtimeSecretsManagerPermissions(
  secrets: Array<{arn:Input<string>;kmsKeyId?:Input<string>}>, region: Input<string>, accountId: Input<string>,
) {
  return [
    {actions:['secretsmanager:GetSecretValue'],resources:secrets.map(secret=>secret.arn)},
    ...secrets.map(secret=>{
      const keyArn=$jsonStringify({id:secret.kmsKeyId??'',region,accountId}).apply(raw=>{
        const value=JSON.parse(raw);
        return aws.kms.getKeyOutput({keyId:value.id||'alias/aws/secretsmanager',region:value.region}).arn.apply(arn=>{
          if(!arn.startsWith(`arn:aws:kms:${value.region}:${value.accountId}:key/`))throw Error('RuntimeSecretKeyScope');
          return arn;
        });
      });
      return {actions:['kms:Decrypt'],resources:[keyArn],conditions:[
        {test:'StringEquals',variable:'kms:ViaService',values:[$interpolate`secretsmanager.${region}.amazonaws.com`]},
        {test:'ArnEquals',variable:'kms:EncryptionContext:SecretARN',values:[secret.arn]},
      ]};
    }),
  ];
}
