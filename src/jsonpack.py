# Copyright (c) 2013, Rodrigo González, Sapienlab All Rights Reserved.
# Available via MIT LICENSE. See https://github.com/roro89/jsonpack/blob/master/LICENSE.md for details.

TOKEN_TRUE = -1
TOKEN_FALSE = -2
TOKEN_NULL = -3
TOKEN_EMPTY_STRING = -4
TOKEN_UNDEFINED = -5

def pack(json):
    json = json if isinstance(json, str) else json
    dictionary = {
        'strings': [],
        'integers': [],
        'floats': []
    }

    def recursiveAstBuilder(item):
        if item is None:
            return {
                'type': 'null',
                'index': TOKEN_NULL
            }
        if item == '':
            return {
                'type': '',
                'index': TOKEN_UNDEFINED
            }
        if isinstance(item, list):
            ast = ['@']
            for i in item:
                ast.append(recursiveAstBuilder(i))
            return ast
        if isinstance(item, dict):
            ast = ['$']
            for key, value in item.items():
                ast.append(recursiveAstBuilder(key))
                ast.append(recursiveAstBuilder(value))
            return ast
        if item == '':
            return {
                'type': 'empty',
                'index': TOKEN_EMPTY_STRING
            }
        if type(item) == type(True):
            return {
                'type': 'boolean',
                'index': TOKEN_TRUE if item else TOKEN_FALSE
            }
        if isinstance(item, str):
            index = dictionary['strings'].index(item) if item in dictionary['strings'] else -1
            if index == -1:
                dictionary['strings'].append((item))
                index = len(dictionary['strings']) - 1
            return {
                'type': 'strings',
                'index': index
            }
        if isinstance(item, int):
            index = dictionary['integers'].index(item) if item in dictionary['integers'] else -1
            if index == -1:
                dictionary['integers'].append(_base10To36(item))
                index = len(dictionary['integers']) - 1
            return {
                'type': 'integers',
                'index': index
            }
        if isinstance(item, float):
            index = dictionary['floats'].index(item) if item in dictionary['floats'] else -1
            if index == -1:
                dictionary['floats'].append(item)
                index = len(dictionary['floats']) - 1
            return {
                'type': 'floats',
                'index': index
            }
        raise TypeError('Unexpected argument of type ' + str(type(item)))

    def recursiveParser(item):
        if isinstance(item, list):
            packed = item[0]
            for i in item[1:]:
                packed += recursiveParser(i) + '|'
            return (packed[:-1] if packed[-1] == '|' else packed) + ']'
        type = item['type']
        index = item['index']
        if type == 'strings':
            return _base10To36(index)
        if type == 'integers':
            return _base10To36(stringLength + index)
        if type == 'floats':
            return _base10To36(stringLength + integerLength + index)
        if type == 'boolean':
            return str(index)
        if type == 'null':
            return str(TOKEN_NULL)
        if type == '':
            return str(TOKEN_UNDEFINED)
        if type == 'empty':
            return str(TOKEN_EMPTY_STRING)
        raise TypeError('The item is alien!')

    ast = recursiveAstBuilder(json)

    stringLength = len(dictionary['strings'])
    integerLength = len(dictionary['integers'])
    floatLength = len(dictionary['floats'])
    packed = '|'.join(dictionary['strings'])
    packed += '^' + '|'.join(dictionary['integers'])
    dictionary['floats'] = [str(n) for n in dictionary['floats']]
    packed += '^' + '|'.join(dictionary['floats'])
    packed += '^' + recursiveParser(ast)

    return packed

def unpack(packed):
    rawBuffers = packed.split('^')
    dictionary = []
    buffer = rawBuffers[0]
    if buffer != '':
        buffer = buffer.split('|')
        for i in buffer:
            dictionary.append(_decode(i))
    buffer = rawBuffers[1]
    if buffer != '':
        buffer = buffer.split('|')
        for i in buffer:
            dictionary.append(_base36To10(i))
    buffer = rawBuffers[2]
    if buffer != '':
        buffer = buffer.split('|')
        for i in buffer:
            dictionary.append(float(i))
    tokens = []
    number36 = ''
    for i in rawBuffers[3]:
        if i in ['|', '$', '@', ']']:
            if number36:
                tokens.append(_base36To10(number36))
                number36 = ''
            if i != '|':
                tokens.append(i)
        else:
            number36 += i
    tokensLength = len(tokens)
    tokensIndex = 0

    def recursiveUnpackerParser():
        nonlocal tokensIndex
        # Maybe '$' (object) or '@' (array)
        type = tokens[tokensIndex]
        tokensIndex += 1
        # Parse an array
        if type == '@':
            node = []
            while tokensIndex < tokensLength:
                value = tokens[tokensIndex]
                if value == ']':
                    return node
                if value == '@' or value == '$':
                    node.append(recursiveUnpackerParser())
                else:
                    if value == TOKEN_TRUE:
                        node.append(True)
                    elif value == TOKEN_FALSE:
                        node.append(False)
                    elif value == TOKEN_NULL:
                        node.append(None)
                    elif value == TOKEN_UNDEFINED:
                        node.append()
                    elif value == TOKEN_EMPTY_STRING:
                        node.append('')
                    else:
                        node.append(dictionary[value])
                tokensIndex += 1
            return node
        # Parse an object
        if type == '$':
            node = {}
            while tokensIndex < tokensLength:
                key = tokens[tokensIndex]
                if key == ']':
                    return node
                if key == TOKEN_EMPTY_STRING:
                    key = ''
                else:
                    key = dictionary[key]
                tokensIndex += 1
                value = tokens[tokensIndex]
                if value == '@' or value == '$':
                    node[key] = recursiveUnpackerParser()
                else:
                    if value == TOKEN_TRUE:
                        node[key] = True
                    elif value == TOKEN_FALSE:
                        node[key] = False
                    elif value == TOKEN_NULL:
                        node[key] = None
                    elif value == TOKEN_UNDEFINED:
                        node[key] = None
                    elif value == TOKEN_EMPTY_STRING:
                        node[key] = ''
                    else:
                        node[key] = dictionary[value]
                tokensIndex += 1
            return node
        raise TypeError('Bad token ' + str(type) + ' isn\'t a type')

    return recursiveUnpackerParser()

def _indexOfDictionary(dictionary, value):
    if isinstance(value, bool):
        return TOKEN_TRUE if value else TOKEN_FALSE
    if value is None:
        return TOKEN_NULL
    if value == '':
        return TOKEN_UNDEFINED
    if value == '':
        return TOKEN_EMPTY_STRING
    if isinstance(value, str):
        value = _encode(value)
        index = dictionary['strings'].index(value) if value in dictionary['strings'] else -1
        if index == -1:
            dictionary['strings'].append(value)
            index = len(dictionary['strings']) - 1
    if type(value) not in [str, int]:
        raise Error('The type is not a JSON type')
    if isinstance(value, str):
        value = _encode(value)
    elif isinstance(value, int) and value % 1 == 0:
        value = _base10To36(value)
    value = _encode(value) if isinstance(value, str) else _base10To36(value)
    index = dictionary[type(value)].index(value) if value in dictionary[type(value)] else -1
    if index == -1:
        dictionary[type(value)].append(value)
        index = len(dictionary[type(value)]) - 1
    return '+' + str(index) if type(value) == 'number' else index

def _encode(string):
    if not isinstance(string, str):
        return string
    return string.replace(' ', '+').replace('+', '%2B').replace('|', '%7C').replace('^', '%5E').replace('%', '%25')

def _decode(string):
    if not isinstance(string, str):
        return string
    return string.replace('+', ' ').replace('%2B', '+').replace('%7C', '|').replace('%5E', '^').replace('%25', '%')

def _base10To36(number):
    if not isinstance(number, (int, float)):
        raise TypeError('number must be an integer')
    is_negative = number < 0
    number = abs(number)

    alphabet, base36 = ['0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', '']

    while number:
        number, i = divmod(number, 36)
        base36 = alphabet[i] + base36
    if is_negative:
        base36 = '-' + base36

    return base36 or alphabet[0]


def _base36To10(number):
    return int(number, 36)

def _indexOf(array, obj, start=0):
    for i in range(start, len(array)):
        if array[i] == obj:
            return i
    return -1