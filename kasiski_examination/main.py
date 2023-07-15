import time
import numpy as np
import re
from itertools import product

mi = "Ppqca xqvekg ybnkmazu ybngbal jon i tszm jyim. Vrag voht vrau c tksg. Ddwuo xitlazu vavv raz c vkb qp iwpou."
message = "Ppqca xqvekg ybnkmazu ybngbal jon i tszm jyim. Vrag voht vrau c tksg. Ddwuo xitlazu vavv raz c vkb qp iwpou."

Key = "infosec"
cipher = "Differential Privacy is the state-of-the-art goal for the problem of privacy-preserving data release and privacy-preserving data mining. Existing techniques using differential privacy, however, cannot effectively handle the publication of high-dimensional data. In particular, when the input dataset contains a large number of attributes, existing methods incur higher computing complexity and lower information to noise ratio, which renders the published data next to useless. This proposal aims to reduce computing complexity and signal to noise ratio. The starting point is to approximate the full distribution of high-dimensional dataset with a set of low-dimensional marginal distributions via optimizing score function and reducing sensitivity, in which generation of noisy conditional distributions with differential privacy is computed in a set of low-dimensional subspaces, and then, the sample tuples from the noisy approximation distribution are used to generate and release the synthetic dataset. Some crucial science problems would be investigated below: (i) constructing a low k-degree Bayesian network over the high-dimensional dataset via exponential mechanism in differential privacy, where the score function is optimized to reduce the sensitivity using mutual information, equivalence classes in maximum joint distribution and dynamic programming; (ii)studying the algorithm to compute a set of noisy conditional distributions from joint distributions in the subspace of Bayesian network, via the Laplace mechanism of differential privacy. (iii)exploring how to generate synthetic data from the differentially private Bayesian network and conditional distributions, without explicitly materializing the noisy global distribution. The proposed solution may have theoretical and technical significance for synthetic data generation with differential privacy on business prospects."

length = len(cipher)
flag = np.zeros(length)
for i in range(len(cipher)):
    if (cipher[i] >= 'A' and cipher[i] <= 'Z'):
        flag[i] = 1


# 1.首先对明文进行加密
def encrypt(message, Key):
    message = message.lower()
    Key = Key.lower()
    sum1 = 0
    mi = ""
    for i in range(len(message)):
        if (message[i] >= 'a' and message[i] <= 'z'):
            if (flag[i] == 1):
                temp = (ord(message[i]) + ord(Key[sum1]) - 2 * 97) % 26
                mi = mi + chr(temp + 97 - 32)
                sum1 = (sum1 + 1) % len(Key)
            else:
                temp = (ord(message[i]) + ord(Key[sum1]) - 2 * 97) % 26
                mi = mi + chr(temp + 97)
                sum1 = (sum1 + 1) % len(Key)
        else:
            mi = mi + message[i]
    return mi

print("原文")
print(cipher)
print("key")
print(Key)
print("密文:")
miwen = encrypt(cipher, Key)
print(miwen)
print("--------------------------------------")
print("开始破解")
start_time = time.time()

def decrypt(mi, Key):
    sum1 = 0
    message = ""
    mi = mi.lower()
    Key = Key.lower()
    for i in range(len(mi)):
        if (mi[i] >= 'a' and mi[i] <= 'z'):
            if (flag[i] == 1):
                temp = (ord(mi[i]) - ord(Key[sum1])) % 26
                message = message + chr(temp + 97 - 32)
                sum1 = (sum1 + 1) % len(Key)
            else:
                temp = (ord(mi[i]) - ord(Key[sum1])) % 26
                message = message + chr(temp + 97)
                sum1 = (sum1 + 1) % len(Key)
        else:
            message = message + mi[i]
    return message


def get_spilt_mi(mi):
    mi = mi.upper()
    spilt_mi = ""
    for i in range(len(mi)):
        if (mi[i] >= 'A' and mi[i] <= 'Z'):
            spilt_mi = spilt_mi + mi[i]
    return spilt_mi


def find_all(sub, s):
    index_list = []
    index = s.find(sub)
    while index != -1:
        index_list.append(index)
        index = s.find(sub, index + 1)

    if len(index_list) > 0:
        return index_list
    else:
        return -1


def find_repeat_sequences_spacings(spilt_mi):
    dict = {}
    submi = ""
    for i in range(3, 6):
        for j in range(len(spilt_mi)):
            submi = spilt_mi[j:j + i]
            index_list = find_all(submi, spilt_mi)
            if (len(submi) == i and dict.__contains__(submi) == False and len(index_list) > 1):
                location = []
                for l in range(len(index_list)):
                    for w in range(l + 1, len(index_list)):
                        location.append(index_list[w] - index_list[l])
                dict[submi] = location
    return dict


# 求所有数的因子
def get_useful_factors(n):
    if n == 0: return [0]
    if n == 1: return [1]
    rlist = []
    for i in range(1, n + 1):
        if n % i == 0:
            rlist.append(i)

    return rlist


def find_key_length(dict):
    key_length = []
    for key in dict:
        location = dict[key]
        for i in range(len(location)):
            rlist = get_useful_factors(location[i])
            key_length = key_length + rlist
    return key_length


def all_list(arr):
    result = {}
    for i in set(arr):
        result[i] = arr.count(i)
    return result


def get_key_list(dict):
    key_length = find_key_length(dict)
    result = all_list(key_length)
    result.pop(1)

    result = sorted(result.items(), key=lambda x: x[1], reverse=True)
    key_list = []
    for i in range(len(result)):
        key_list.append(result[i][0])

    return key_list


def get_nth_subkeys_letters(n, key_length, spilt_mi):
    result = ""
    for i in range(0, len(spilt_mi), key_length):
        if (i + n - 1 <= (len(spilt_mi) - 1)):
            result = result + spilt_mi[i + n - 1]

    return result

def strcount(a):
    # 定义一个空字典
    b = {}
    # 求出字符串的长度
    c = len(a)
    i = 0
    while i < c:
        if a[i] in b:
            b[a[i]] += 1
        else:
            b[a[i]] = 1
        i += 1
    # 遍历字典
    return b


def freq_match_score(spilt_mi):
    ETAOIN = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    freq1 = strcount(spilt_mi)

    freq2 = {}

    freq1 = sorted(freq1.items(), key=lambda x: x[1], reverse=True)
    for i in range(len(freq1)):
        if freq1[i][1] not in freq2.keys():
            list1 = [freq1[i][0]]
            temp = {freq1[i][1]: list1}
            freq2.update(temp)
        else:
            freq2[freq1[i][1]].append(freq1[i][0])

    zimu = []
    zimubiao = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    for key1 in freq2:
        freq2[key1].sort(key=ETAOIN.find, reverse=True)
        zimu = zimu + freq2[key1]
    appear = np.ones(26)
    for i in range(len(zimubiao)):
        if (zimubiao[i] not in zimu):
            appear[i] = 0
    rest = []

    for i in range(len(zimubiao)):
        if appear[i] == 0:
            temp = chr(i + 65)
            rest.append(temp)
    if (len(rest) == 0):
        zimu.sort(key=ETAOIN.find, reverse=True)
    else:
        rest.sort(key=ETAOIN.find, reverse=True)
        zimu = zimu + rest

    score = 0
    # 分别取前六个和后六个
    front = ETAOIN[0:6]
    back = ETAOIN[-6:]

    for i in range(6):
        if (zimu[i] in front):
            score = score + 1
    for i in range(20, 26):
        if (zimu[i] in back):
            score = score + 1
    return score


def is_english(mi, word_percentage=20, letter_percentage=85):
    with open("dictionary.txt", "r") as f:
        dictionary = f.read().splitlines()  # 获取 文件全部数据 不要回车, 返回结果是一个列表
    mi = mi.upper()
    pat = '[a-zA-Z]+'
    lst = re.findall(pat, mi)
    W = 0
    M = len(lst)

    for i in range(M):
        if lst[i] in dictionary:
            W = W + 1
    word = (W / M) * 100
    L = 0
    C = len(mi)
    for i in range(C):
        if (mi[i] >= 'A' and mi[i] <= 'Z'):
            L = L + 1
        if (mi[i] == " "):
            L = L + 1
    letter = (L / C) * 100
    if (word >= word_percentage and letter >= letter_percentage):
        flag = True
    else:
        flag = False
    return flag


zimu = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


spilt_cipher = get_spilt_mi(miwen)

dict = find_repeat_sequences_spacings(spilt_cipher)

# 获取可能的密钥长度
key_list = get_key_list(dict)

flag1 = 0
for i in range(len(key_list)):
    if flag1 == 1:
        break
    print("key长度")
    print(key_list[i])
    possile_key = []
    for j in range(1, key_list[i] + 1):
        series = get_nth_subkeys_letters(j, key_list[i], spilt_cipher)
        key = {}
        son_key = ""
        for k in range(len(zimu)):
            message = decrypt(series, zimu[k])
            message = message.upper()
            fsocre = freq_match_score(message)
            temp = {zimu[k]: fsocre}
            key.update(temp)
            key_sort = sorted(key.items(), key=lambda x: x[1], reverse=True)
        for m in range(key_list[i]):
            son_key = son_key + key_sort[m][0]
        # 获取列表
        possile_key.append(son_key)
    key_com = []
    for l in product(*possile_key):
        key_com.append(l)
    # ss1=''.join(key_com[0])
    # 开始遍历所有的组合判断是否符合条件
    for y in range(len(key_com)):
        p_key = ''.join(key_com[y])
        de = decrypt(miwen, p_key)
        if (is_english(de)):
            print("破解后的密文为:")
            print(de)
            with open("result.txt", "w", encoding='utf-8') as f:
                f.write(de)
                f.close()
            print("密钥为:")
            print(p_key)
            flag1 = 1
            break
end_time = time.time()
print("运行时间{}".format(end_time-start_time))