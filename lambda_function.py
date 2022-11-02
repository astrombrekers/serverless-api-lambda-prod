import json
import boto3
import logging
from custom_encoder import CustomEncoder
logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('product-tbl')

getMethod = 'GET'
postMethod = 'POST'
patchMethod = 'PATCH'
deleteMethod = 'DELETE'
healthPath = '/health'
productPath = '/product'
productsPath = '/products'


def lambda_handler(event, context):
    logger.info(event)
    http_method = event['httpMethod']
    path = event['path']
    if http_method == getMethod and path == healthPath:
        response = build_response(200)
    elif http_method == getMethod and path == productPath:
        response = get_product(event['queryStringParameters']['prod_id'])
    elif http_method == getMethod and path == productsPath:
        response = get_products()
    elif http_method == postMethod and path == productPath:
        response = save_product(json.loads(event['body']))
    elif http_method == patchMethod and path == productPath:
        request_body = json.loads(event['body'])
        response = update_product(request_body['prod_id'], request_body['updateKey'], request_body['updateValue'])
    elif http_method == deleteMethod and path == productPath:
        request_body = json.loads(event['body'])
        response = delete_product(request_body['prod_id'])
    else:
        response = build_response(404, 'Not Found')

    return response


def get_product(prod_id):
    try:
        response = table.get_item(
            Key={
                'prod_id': prod_id
            }
        )
        if 'Item' in response:
            return build_response(200, response['Item'])
        else:
            return build_response(404, {'Message': f'Product id {prod_id} not found'})
    except:
        logger.exception(f'Message: Product id prod_id not found')


def get_products():
    try:
        response = table.scan()
        result = response['Items']
        print(result)

        while 'LastEvaluatedKey' in response:
            response.table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
            result.extend(response['Items'])

        body = {
            'products': result
        }
        print('test')
        return build_response(200, body)
    except:
        logger.exception('Error')


def save_product(request_body):
    try:
        table.put_item(Item=request_body)
        body = {
            'Operation': 'SAVE',
            'Message': 'SUCCESS',
            'Item': request_body
        }
        return build_response(200, body)
    except:
        logger.exception('Error Save failed')


def update_product(prod_id, update_key, update_value):
    try:
        response = table.update_item(
            Key={'prod_id': prod_id},
            UpdateExpression='set %s = :value' % update_key,
            ExpressionAttributeValues={':value': update_value},
            ReturnValues='UPDATED_NEW'
        )
        body = {
            'Operation': 'UPDATE',
            'Message': 'SUCCESS',
            'Item': response
        }
        return build_response(200, body)
    except:
        logger.exception('Error: Update failed')


def delete_product(prod_id):
    try:
        response = table.delete_item(
            Key={'prod_id': prod_id},
            ReturnValues='ALL_OLD'
        )
        body = {
            'Operation': 'DELETE',
            'Message': 'SUCCESS',
            'DeleteItem': response
        }
        return build_response(200, body)
    except:
        logger.exception('Error: Delete failed')


def build_response(status_code, body=None):
    response = {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    }
    if body is not None:
        response['body'] = json.dumps(body, cls=CustomEncoder)
    return response
