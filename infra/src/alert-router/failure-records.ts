interface JsonRecord {
  [key: string]: unknown;
}

export interface TransportFailureSummary {
  messageId: string;
  notificationType: string;
  topicArn: string;
}

export interface ExecutionFailureSummary {
  approximateInvokeCount: number;
  condition: string;
  functionArn: string;
  requestId: string;
}

function asRecord(value: unknown): JsonRecord | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return;
  return value as JsonRecord;
}

function parseRecord(body: string): JsonRecord | undefined {
  try {
    return asRecord(JSON.parse(body));
  } catch {
    return;
  }
}

function stringField(record: JsonRecord, field: string): string | undefined {
  const value = record[field];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

export function parseTransportFailure(body: string): TransportFailureSummary {
  const record = parseRecord(body);
  const notificationType = record && stringField(record, "Type");
  const messageId = record && stringField(record, "MessageId");
  const topicArn = record && stringField(record, "TopicArn");
  const message = record && stringField(record, "Message");

  if (notificationType !== "Notification" || !messageId || !topicArn || !message) {
    throw new Error("not an SNS transport failure record");
  }

  return { messageId, notificationType, topicArn };
}

export function parseExecutionFailure(body: string): ExecutionFailureSummary {
  const record = parseRecord(body);
  const requestContext = record && asRecord(record.requestContext);
  const condition = requestContext && stringField(requestContext, "condition");
  const functionArn = requestContext && stringField(requestContext, "functionArn");
  const requestId = requestContext && stringField(requestContext, "requestId");
  const approximateInvokeCount = requestContext?.approximateInvokeCount;
  const hasDestinationShape =
    record?.version === "1.0" &&
    Object.hasOwn(record, "requestPayload") &&
    Object.hasOwn(record, "responseContext") &&
    Object.hasOwn(record, "responsePayload");

  if (
    !hasDestinationShape ||
    !condition ||
    !functionArn ||
    !requestId ||
    typeof approximateInvokeCount !== "number" ||
    !Number.isInteger(approximateInvokeCount) ||
    approximateInvokeCount < 1
  ) {
    throw new Error("not a Lambda execution failure record");
  }

  return { approximateInvokeCount, condition, functionArn, requestId };
}
