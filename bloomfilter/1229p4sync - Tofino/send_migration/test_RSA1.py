#测试RSA加密解密过程，需要借助send_RSA发包
import binascii
import sys
sys.path.append('/home/zjlab/.local/lib/python3.8/site-packages')

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import Crypto.Hash.SHA512
import base64
from scapy.all import *
from myTunnel_header import  MyTunnel, Signature,TYPE_IPV4
# sign 私钥生成签名和公钥验证签名

private_key = '''-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQD1t3KRf4oS3sH8PbABbXL1KBYCnGq4C/yinpfQ2j2eUmZarHuw
IMT9y5ns1lpZZTktGnypvnQjF8c0Rr/cYU53DJjglAgVEb3el6iU+WZ7nwLub/BN
YS83zpzrhDE3Qy6qTM3evsUsekBR8x6f6Usl7KpEI/0b+EfRSpXDdvU64wIDAQAB
AoGBAJK0odHfPTgBCf8pcaGYkG9xLJsIeutCNOd/GxOWif2yIux2WS8SkasaWd+/
J5iCSD32t4G9dafSNZyvtTPGYUqll4aGXlFqNW8pm16HPQXWrhv1D5LVEEu3zbj+
iNG+gHwB4bISQAOJbnvB6GoFUbDf8VYwkGGlSLGw5D5tulhRAkEA/XBLTfj+5j40
QPfuRIhcBsgxynKJDcmV0sLAIOTBIfSKs5nuYHEVEOcGaxS+nPY3w1ffSUPUdxm0
7L2s+9c0SQJBAPgzLLFvUjM58J/AtklkGyJ3KK5W+jLi/N1PIw7CGYGM2yfFiQLR
ibtJVjTFhLKqDz/BK4lZ9ffU/VNHSApOncsCQQCRBzSgnw9GtGv0jaxUnW+EFgWg
IyDYufW5kOafLCh1BNpmYnztxWhXrsyWdF2Ltr48U8mbxGwN57EIFJar2v+5AkA7
GkSMRAv48tUf1Y4Sz+m+PU3Mph2SPIcmVA/vFb1pIheV0u4bY7Y+iOokStychu52
qhMp8+gkie2BBTpcafgdAkBw8bAzLgmCV8SZEN60x8c2M2Y95CoYOoMLjvQdEfen
IeDmun3DtAPBuStwYNfeQnAHCwvcOJsgDiRLzhys3056
-----END RSA PRIVATE KEY-----'''

public_key = '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD1t3KRf4oS3sH8PbABbXL1KBYC
nGq4C/yinpfQ2j2eUmZarHuwIMT9y5ns1lpZZTktGnypvnQjF8c0Rr/cYU53DJjg
lAgVEb3el6iU+WZ7nwLub/BNYS83zpzrhDE3Qy6qTM3evsUsekBR8x6f6Usl7KpE
I/0b+EfRSpXDdvU64wIDAQAB
-----END PUBLIC KEY-----'''

def handle_pkt(pkt):
    if MyTunnel in pkt and Signature in pkt and int(pkt["Signature"].protocol) == 1:
        proto = str(pkt["MyTunnel"].pid)
        load_sketch = str(pkt["MyTunnel"].load_sketch)
        message = proto + load_sketch

        pri_key = RSA.importKey(private_key)# RSA 的 importKey() 方法将读取的私钥字符串 处理成可用的私钥用于生成签名
        signer = PKCS1_v1_5.new(pri_key)# 实例化一个签名对象 signer  传入处理后的私钥
        digest = Crypto.Hash.SHA512.new()# 信息需要先转换成 sha 字符串
        digest.update(message.encode("utf8"))
        sign = signer.sign(digest)# 对信息生成签名
        sign_send = base64.b16encode(sign)# 生成的签名是字节串 将结果转16进制字符
        # print("sign:**********",sign,"**********")
        # print("sign_send:**********", sign_send, "**********")
        pkt["Signature"].signature = int(sign_send,16)#16进制转10进制，才能存到包里
        pkt["Signature"].protocol = TYPE_IPV4
        sendp(pkt, iface="ens3f1np1", verbose=False)
        pkt.show2()

    if Signature in pkt and int(pkt["Signature"].protocol) == TYPE_IPV4:
        # 使用公钥验证签名
        proto = str(pkt["MyTunnel"].pid)
        load_sketch = str(pkt["MyTunnel"].load_sketch)
        message = proto + load_sketch

        pub_key = RSA.importKey(public_key)# RSA 的 importKey() 方法将读取的公钥字符串 处理成可用的公钥用于验证签名
        verifier = PKCS1_v1_5.new(pub_key)# 实例化一个验证对象 verifier ，传入处理的公钥，
        digest = Crypto.Hash.SHA512.new()
        digest.update(message.encode("utf8"))

        sign_receive = bytes(format(pkt["Signature"].signature,'x'), encoding = "utf8")#包内10进制转为16进制
        # print("sign_send:**********", sign_send, "**********")
        # print("sign_receive:**********", sign_receive, "**********")
        # print(type(sign_receive),type(sign_send))

        sign_result = verifier.verify(digest, base64.b16decode(sign_receive, casefold=True))
        print("verify result:", sign_result)    #casefold 设置仅大写字母识别还是大小写都可以识别

if __name__ == '__main__':
    iface = "ens3f1np1"
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface, prn = lambda x: handle_pkt(x))