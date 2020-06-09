import base64
import random

from Cryptodome.Cipher import AES
from pkcs7 import PKCS7Encoder


class Cryptgraphy:
    ASCII_LENGTH = 128
    AES_BLOCK_SIZE = 128  # AES块大小
    RANDOM_NUM_SIZE = 16  # 随机数长度
    MSG_LENGTH_INFO_SIZE = 4  # 数据长度信息长度

    @classmethod
    def AES_encrypt(cls, unencrypted_data, encodingAESKey, suiteKey):
        """
        加密方法
        :param unencrypted_data: 输入字符串（待加密数据）
        :param encodingAESKey:
        :param suiteKey: 开发应用对应的suiteKey
        加密过程：
            1.组合数据： 随机获取16位字符串 + 4位字符串（信息长度） + 输入字符串+ suiteKey
            2.将数据进行  PKCS7 补位 128Bit
            3.encodingAESKey += "=" 处理后，进行base64解码获取Key，iv为key前16位
            4.将数据进行AES, MODE_CBC模式加密
            5.件加密数据进行进行base64编码
        """
        encoder = PKCS7Encoder(cls.AES_BLOCK_SIZE)

        randomNum = Cryptgraphy._create_randCode(cls.RANDOM_NUM_SIZE)  # 随机获取16位字符串
        msg_lengthInfo = Cryptgraphy._get_stringLength_toByte(unencrypted_data, cls.MSG_LENGTH_INFO_SIZE)  # 4位字符串（信息长度）
        input_info = bytes(unencrypted_data + suiteKey, 'ascii')  # 输入字符串+ suiteKey
        msg = randomNum + msg_lengthInfo + input_info
        msg = encoder.encode(msg)  # 将数据进行  PKCS7 补位 128Bit

        encodingAESKey = encodingAESKey + "="
        key = base64.b64decode(encodingAESKey.encode("utf-8"))
        iv = key[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher.block_size = cls.AES_BLOCK_SIZE
        msg = cipher.encrypt(msg)
        encrypt_data = base64.b64encode(msg)
        return encrypt_data.decode("utf-8")

    @classmethod
    def _get_stringLength_toByte(cls, unencrypted_data, total_length=4):
        input_len = len(unencrypted_data)
        result = []
        res = int(input_len / cls.ASCII_LENGTH)
        while res != 0:
            result.append(input_len % cls.ASCII_LENGTH)
            input_len = res
            res = int(input_len / cls.ASCII_LENGTH)
        if res == 0:
            result.append(input_len % cls.ASCII_LENGTH)
        if len(result) < total_length:
            for i in range(total_length - len(result)):
                result.append(0)

        result.reverse()
        return bytes(''.join([chr(x) for x in result]), 'ascii')

    @staticmethod
    def _create_randCode(codeLen):
        codeSerial = "2,3,4,5,6,7,a,c,d,e,f,h,i,j,k,m,n,p,r,s,t,A,C,D,E,F,G,H,J,K,M,N,P,Q,R,S,U,V,W,X,Y,Z"
        if codeLen == 0:
            codeLen = 16
        arr = codeSerial.split(',')
        code_arr = []
        for i in range(codeLen):
            index = random.randint(0, len(arr) - 1)
            code_arr.append(arr[index])
        return bytes(''.join(code_arr), 'ascii')

    @classmethod
    def AES_decrypt(cls, encrypt_data, encodingAESKey, suiteKey):
        """
        解密方法
        :param suiteKey:
        :param input:
        :param encodingAESKey:
        """
        encrypt_data = base64.b64decode(encrypt_data.encode("utf-8"))
        key = base64.b64decode((encodingAESKey + "=").encode("utf-8"))
        iv = key[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher.block_size = cls.AES_BLOCK_SIZE

        msg = cipher.decrypt(encrypt_data)
        encoder = PKCS7Encoder(cls.AES_BLOCK_SIZE)
        msg = encoder.decode(msg)
        msg_start = cls.RANDOM_NUM_SIZE + cls.MSG_LENGTH_INFO_SIZE
        msg_length_info = msg[cls.RANDOM_NUM_SIZE:msg_start]

        msg_length = Cryptgraphy.bytes_to_number(msg_length_info)

        data = msg[msg_start:-1 * len(suiteKey)].decode("utf-8")
        corid = msg[-1 * len(suiteKey):].decode("utf-8")
        if len(data) != msg_length:
            raise Exception("长度不对")
        return data, corid

    @staticmethod
    def bytes_to_number(data):
        num = 0
        for i, value in enumerate(data[::-1]):
            num += pow(128, i) * value
        return num
