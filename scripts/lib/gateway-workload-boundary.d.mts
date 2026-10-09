export const GATEWAY_BOUNDARY_POLICY_NAME: string;
export const GATEWAY_ROLE_TOKENS: readonly string[];
export const GATEWAY_LOGICAL_ROLES: readonly string[];
export function gatewayRoleStage(name: string): string | undefined;
export function gatewayRoleArnPatterns(identity: {partition:string;accountId:string}, stage?: string): string[];
export function gatewayBoundaryArn(identity: {partition:string;accountId:string}): string;
export function expectedGatewayBoundaryPolicyDocument(contract: {partition:string;accountId:string;applicationRegion:string;policyRevision?:string}): Record<string,unknown>;
export function gatewayBoundaryProbeCases(contract: {partition:string;accountId:string;applicationRegion:string;policyRevision?:string}): Array<{name:string;expected:string;resource:string;context:string[]}>;
