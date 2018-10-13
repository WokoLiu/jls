# -*- coding: utf-8 -*-
# @Time    : 2018/10/13 19:33
# @Author  : Woko
# @File    : jls.py

"""
http://blog.lanyus.com/archives/174.html
https://www.bennythink.com/jbls.html
http://blog.lanyus.com/archives/174.html/comment-page-21#comments
"""

from flask import Flask, request
import rsa


app = Flask(__name__)

obtain_api = '/' + 'rpc' + '/' + 'obtain' + 'Ticket' + '.' + 'action'


# useful before version 2018.2.1
@app.route(obtain_api)
def obtain_ticket():
    """get by wireshark
    request like this:
    curl -H 'User-Agent: Java/1.8.0_112-release' \
    -H 'Host: idea.iteblog.com' \
    -H 'Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2' \
    --compressed 'http://idea.iteblog.com/key.php/rpc/obtainTicket.action?buildDate=20161123&buildNumber=2016.3+Build+PY-163.8233.8&clientVersion=3&hostName=wokodembp.lan&machineId=97540378-b9da-40ab-9ae8-937a7b62c3a4&productCode=23967154-eb66-4261-b81a-3354e9de6366&productFamilyId=23967154-eb66-4261-b81a-3354e9de6366&salt=1539429136178&secure=false&userName=woko&version=163000&versionNumber=163000'

    response like this:
    <!-- 9e616645403d5725c6c611d34a59d7aef92783d7e59271f40fe8e7bd8f0f0f262462c541a4e47bb7ca6ba84db32f41032e7406233c24673e4559d9428bc71e20 -->
<ObtainTicketResponse><message></message><prolongationPeriod>607875500</prolongationPeriod><responseCode>OK</responseCode><salt>1539429136178</salt><ticketId>1</ticketId><ticketProperties>licensee=woko	licenseType=0	</ticketProperties></ObtainTicketResponse>
    """
    salt = request.values.get('salt')  # input timestamp (ms)
    username = request.values.get('userName')  # input user
    print(request.values)
    if not salt or not username:
        return 'error'

    # jb will verify again after prolongation_period/500 seconds, someone use 607875500
    prolongation_period = str(500 * 14 * 86400)

    # get from wireshark
    xml_content = ('<ObtainTicketResponse>'
                   '<message></message>'
                   '<prolongationPeriod>{}</prolongationPeriod>'
                   '<responseCode>OK</responseCode>'
                   '<salt>{}</salt>'
                   '<ticketId>1</ticketId>'
                   '<ticketProperties>licensee={}\tlicenseType=0\t</ticketProperties>'
                   '</ObtainTicketResponse>'
                   .format(prolongation_period, salt, username))

    xml_signature = sign(xml_content)
    response = '<!-- {} -->\n{}'.format(xml_signature, xml_content)
    return response


def sign(data):
    with open('jls_private.pem') as f:  # still don't know how to get it
        private_key = rsa.PrivateKey.load_pkcs1(f.read())
    signature = rsa.sign(str.encode(data), private_key, 'MD5')
    return signature.hex()  # must be hex


if __name__ == '__main__':
    # app.debug = True
    app.run()
