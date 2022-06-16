// You can edit this code!
// Click here and start typing.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

func main() {
	origData := []byte("b6f51fc15df0df65d1bd90cdbe6c1f5409a4c5a2337c5c2cbeb1ba12a0814de7")

	key := []byte("k2k38drr4g8cck38")
	fmt.Println("明文", string(origData))
	en := AESEncrypt(origData, key)
	fmt.Println("密文", base64.StdEncoding.EncodeToString(en))
	//解密
	de := AESDecrypt(en, key)
	fmt.Println("解密", string(de))

}

//补码
func PKCS7Padding(origData []byte, blockSize int) []byte {
	//计算需要补几位数
	padding := blockSize - len(origData)%blockSize
	//在切片后面追加char数量的byte(char)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(origData, padtext...)
}

//去补码
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:length-unpadding]
}

//加密
func AESEncrypt(origData, key []byte) []byte {
	//获取block块
	block, _ := aes.NewCipher(key)
	//补码
	origData = PKCS7Padding(origData, block.BlockSize())
	//加密模式，
	blockMode := cipher.NewCBCEncrypter(block, key[:block.BlockSize()])
	//创建明文长度的数组
	crypted := make([]byte, len(origData))
	//加密明文
	blockMode.CryptBlocks(crypted, origData)
	return crypted
}

//解密
func AESDecrypt(crypted, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS7UnPadding(origData)
	return origData
}
