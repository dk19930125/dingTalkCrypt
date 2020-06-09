import hashlib
from Cryptgraphy import Cryptgraphy

class ReturnCode(object):
    SUCCESS = 0
    """加密明文文本非法"""
    ENCRYPTION_PLAINTEXT_ILLEGAL = 900001
    """ 加密时间戳参数非法 """
    ENCRYPTION_TIMESTAMP_ILLEGAL = 900002
    """ 加密随机字符串参数非法 """
    ENCRYPTION_NONCE_ILLEGAL = 900003
    """ 不合法的aeskey """
    AES_KEY_ILLEGAL = 900004
    """ 签名不匹配 """
    SIGNATURE_NOT_MATCH = 900005
    """ 计算签名错误 """
    COMPUTE_SIGNATURE_ERROR = 900006
    """ 计算加密文字错误 """
    COMPUTE_ENCRYPT_TEXT_ERROR = 900007
    """ 计算解密文字错误 """
    COMPUTE_DECRYPT_TEXT_ERROR = 900008
    """ 计算解密文字长度不匹配 """
    COMPUTE_DECRYPT_TEXT_LENGTH_ERROR = 900009
    """ 计算解密文字suiteKey不匹配 """
    COMPUTE_DECRYPT_TEXT_SuiteKey_ERROR = 900010


class DingTalkCrypt:
    _AES_ENCODE_KEY_LENGTH = 43  # encodingAESKey固定长度43

    def __init__(self, token, encodingAESKey, suiteKey):
        """
        :param token: 开发者设置的token
        :param encodingAESKey: 开发者设置的encodingAESKey
        :param suiteKey: 开发应用对应的suiteKey
        """
        self._token = token
        self._encodingAESKey = encodingAESKey
        self._suiteKey = suiteKey

    def decrypt_msg(self, msgSignature, timeStamp, nonce, encryptStr):
        """
        解密函數
        :param msgSignature:
        :param timeStamp:
        :param nonce:
        :param encryptStr:
        :return: (ReturnCode, Msg)
        """
        if len(self._encodingAESKey) != self._AES_ENCODE_KEY_LENGTH:
            return ReturnCode.AES_KEY_ILLEGAL, ""
        ret = self._verifySignature(self._token, timeStamp, nonce, encryptStr, msgSignature)
        if ret != ReturnCode.SUCCESS:
            return ret, ""
        try:
            msg, corpid = Cryptgraphy.AES_decrypt(encryptStr, self._encodingAESKey, self._suiteKey)
        except:
            return ReturnCode.COMPUTE_DECRYPT_TEXT_SuiteKey_ERROR, ""
        if corpid != self._suiteKey:
            return ReturnCode.COMPUTE_DECRYPT_TEXT_SuiteKey_ERROR, ""
        return ReturnCode.SUCCESS, msg

    def encrypt_msg(self, sReplyMsg, sTimeStamp, sNonce):
        """
        加密
        :param sReplyMsg:
        :param sTimeStamp:
        :param sNonce:
        :return:
        """
        if sReplyMsg.strip() == '':
            return ReturnCode.ENCRYPTION_PLAINTEXT_ILLEGAL, "", ""
        if sTimeStamp.strip() == '':
            return ReturnCode.ENCRYPTION_TIMESTAMP_ILLEGAL, "", ""
        if sNonce.strip() == '':
            return ReturnCode.ENCRYPTION_NONCE_ILLEGAL, "", ""
        if len(self._encodingAESKey) != self._AES_ENCODE_KEY_LENGTH:
            return ReturnCode.AES_KEY_ILLEGAL, "", ""
        try:
            data = Cryptgraphy.AES_encrypt(sReplyMsg, self._encodingAESKey, self._suiteKey)
            data = data

            ret, signature = self._generateSignature(self._token, sTimeStamp, sNonce, data)
            if ret != ReturnCode.SUCCESS:
                return ret, '', ""
            return ReturnCode.SUCCESS, data, signature
        except Exception as e:
            print(e)
            return ReturnCode.AES_KEY_ILLEGAL, "", ""

    @classmethod
    def _verifySignature(cls, token, timeStamp, nonce, encryptStr, msgSignature):
        ret, hash = cls._generateSignature(token, timeStamp, nonce, encryptStr)
        if ret != ReturnCode.SUCCESS:
            return ret
        if hash == msgSignature:
            return ReturnCode.SUCCESS
        else:
            return ReturnCode.SIGNATURE_NOT_MATCH

    @classmethod
    def _generateSignature(cls, token, timeStamp, nonce, encryptStr):
        """
        生成签名
        :param token:
        :param timeStamp:
        :param nonce:
        :param encryptStr:
        """
        try:
            arr = [token, timeStamp, nonce, encryptStr]
            arr.sort()
            row = ""
            for i in arr:
                row += i
            sha1 = hashlib.sha1(row.encode(encoding='UTF-8')).hexdigest()
            return ReturnCode.SUCCESS, sha1
        except Exception as e:
            return ReturnCode.COMPUTE_SIGNATURE_ERROR, ''


if __name__ == "__main__":
    signature = '5a65ceeef9aab2d149439f82dc191dd6c5cbe2c0'
    timestamp = '1445827045067'
    # timestamp = '1591683225'
    nonce = 'nEXhMP4r'
    encrypt = '1a3NBxmCFwkCJvfoQ7WhJHB+iX3qHPsc9JbaDznE1i03peOk1LaOQoRz3+nlyGNhwmwJ3vDMG+OzrHMeiZI7gTRWVdUBmfxjZ8Ej23JVYa9VrYeJ5as7XM/ZpulX8NEQis44w53h1qAgnC3PRzM7Zc/D6Ibr0rgUathB6zRHP8PYrfgnNOS9PhSBdHlegK+AGGanfwjXuQ9+0pZcy0w9lQ=='

    TOKEN = '123456'
    AES_KEY = "4g5j64qlyl3zvetqxz5jiocdr586fn2zvjpa8zls3ij"
    KEY = 'suite4xxxxxxxxxxxxxxx'
    d = DingTalkCrypt(TOKEN, AES_KEY, KEY)

    s = 'dd'
    # for i in range(12342):
    #     s += "i"
    # ret, encrypt, signature = d.encrypt_msg(s, timestamp, nonce)
    # print(ret, encrypt, signature)
    print(d.decrypt_msg(signature, timestamp, nonce, encrypt))
