import boto3
import json

config = boto3.client('config')
access_analyzer_client = boto3.client('accessanalyzer')
APPLICABLE_RESOURCES = ["AWS::S3::Bucket", "AWS::SQS::Queue", "AWS::SNS::Topic", "AWS::Lambda::Function"]


def evaluate_compliance(configuration_item):
    # Start as non-compliant
    compliance_type = 'NON_COMPLIANT'
    annotation = 'Policy is non-compliant.'

    if configuration_item['configurationItemStatus'] == "ResourceDeleted":
        compliance_type = 'NOT_APPLICABLE'
        annotation = "The resource was deleted."

    elif configuration_item["resourceType"] not in APPLICABLE_RESOURCES:
        compliance_type = 'NOT_APPLICABLE'
        annotation = f"The rule doesn't apply to resources of type {configuration_item['resourceType']}"

    else:
        try:
            if configuration_item["resourceType"] == 'AWS::S3::Bucket':
                policy_document = configuration_item['supplementaryConfiguration']['BucketPolicy'][
                    'policyText']
            elif configuration_item["resourceType"] == 'AWS::SQS::Queue':
                policy_document = configuration_item['configuration']['Policy']
            elif configuration_item["resourceType"] == 'AWS::SNS::Topic':
                policy_document = configuration_item['configuration']['Policy']
            elif configuration_item["resourceType"] == 'AWS::Lambda::Function':
                policy_document = configuration_item['supplementaryConfiguration']['Policy']

            if policy_document is None:
                return {
                    "compliance_type": "COMPLIANT",
                    "annotation": "Policy is empty"
                }

            if configuration_item["resourceType"] != 'AWS::S3::Bucket':
                sample_s3_resource = "arn:aws:s3:::sampleBucket/*"
                policy_document = json.loads(policy_document)
                for statement in policy_document['Statement']:
                    statement['Action'] = 's3:GetObject'
                    statement['Resource'] = sample_s3_resource
                policyDocument = json.dumps(policy_document)
            else:
                policyDocument = policy_document

            # Validate the policy using Access Analyzer
            validation_response = access_analyzer_client.validate_policy(policyType='RESOURCE_POLICY',
                                                                         policyDocument=policyDocument,
                                                                         validatePolicyResourceType='AWS::S3::Bucket')

            # Check for the specific finding
            findings = validation_response.get('findings', [])
            exist = False
            for finding in findings:
                if 'findingDetails' in finding:
                    finding_details = finding['findingDetails']
                    if 'Granting access to a service principal without specifying a source is overly permissive.' in finding_details:
                        exist = True
                        annotation = "Granting access to a service principal without specifying a source is overly permissive."
                        break

            if not exist:
                compliance_type = 'COMPLIANT'
                annotation = 'Policy is compliant.'
        except Exception as e:
            compliance_type = 'NON_COMPLIANT'
            annotation = f'Error validating policy: {str(e)}'

    return {
        "compliance_type": compliance_type,
        "annotation": annotation
    }


def lambda_handler(event, context):
    invoking_event = json.loads(event['invokingEvent'])

    # Check for oversized item
    if "configurationItem" in invoking_event:
        configuration_item = invoking_event["configurationItem"]
    elif "configurationItemSummary" in invoking_event:
        configuration_item = invoking_event["configurationItemSummary"]

    evaluation = evaluate_compliance(configuration_item)
    print('Compliance evaluation for %s: %s' % (configuration_item['resourceId'], evaluation["compliance_type"]))
    print('Annotation: %s' % (evaluation["annotation"]))
    response = config.put_evaluations(
        Evaluations=[
            {
                'ComplianceResourceType': invoking_event['configurationItem']['resourceType'],
                'ComplianceResourceId': invoking_event['configurationItem']['resourceId'],
                'ComplianceType': evaluation["compliance_type"],
                "Annotation": evaluation["annotation"],
                'OrderingTimestamp': invoking_event['configurationItem']['configurationItemCaptureTime']
            },
        ],
        ResultToken=event['resultToken'])
