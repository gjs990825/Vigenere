# Vigenère cipher

Vigenere encryption, decryption and ciphertext-only attack in python. [@gjs990825](https://github.com/gjs990825)  
Check [Vigenère cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher) on Wikipedia for more information.

---

## Assignments

多表代换Virginia加密算法及秘钥破解算法的实现：编程语言为C语言或其它语言，要求提交加密、解密、破解源代码文件。

- 实现对任意有意义的英文文本文件（*.txt）的Virginia加密、解密算法，其中秘钥是任意输入的一个字符串。要求提供明文文本文件、密文文本文件。
- 在不知道秘钥的情况下，对一个用Virginia加密算法生成的密文文本文件进行破解，包括破解秘钥、生成对应的明文。要求提供程序测试说明文档。

---

## [vigenere.ipynb](vigenere.ipynb)

Interactive Jupyter Notebook to play with, click title to open notebook.

---

## [vigenere.py](vigenere.py)

A Python script able to perform required functions. Type `python vigenere.py {normal, crack} -h`
in command-line for its usage.  
Support standard input, output.

### Encryption

```bash
python vigenere.py normal -e -k infosec original.txt encrypted.txt
```

### Decryption

```bash
python vigenere.py normal -d -k infosec encrypted.txt decrypted.txt
```

### Cracking

```bash
python vigenere.py crack cipher_to_break.txt breaking_results.txt
```

### stdin as input, stdout as output

```bash
cat original.txt | python vigenere.py normal -e -k infosec
```