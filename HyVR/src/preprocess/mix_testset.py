import json
import os
import random

def mix_testset():
    """混合所有CWE测试集，移除CWE标志，打乱顺序"""
    
    # CWE列表
    cwe_list = ['119', '125', '200', '20', '264', '362', '401', '416', '476', '787']
    
    all_samples = []
    
    # 读取每个CWE的测试集
    for cwe in cwe_list:
        filename = f'Linux_kernel_CWE-{cwe}_testset.json'
        filepath = os.path.join('src', 'data', 'test', filename)
        
        if not os.path.exists(filepath):
            print(f"警告: 文件不存在: {filepath}")
            continue
        
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # 移除CWE标志，保留原始CWE信息
        for item in data:
            # 删除CWE相关字段
            if 'CWE' in item:
                del item['CWE']
            if 'cwe_id' in item:
                del item['cwe_id']
            
            # 从cwe字段提取原始CWE信息（隐藏的）
            original_cwe = None
            if 'cwe' in item:
                cwe_list = item['cwe']
                if isinstance(cwe_list, list) and cwe_list:
                    original_cwe = cwe_list[0]  # 取第一个CWE
                del item['cwe']  # 删除cwe字段
            else:
                original_cwe = f'CWE-{cwe}'  # 使用文件名中的CWE
            
            item['original_cwe'] = original_cwe
            
            all_samples.append(item)
    
    # 打乱顺序
    random.shuffle(all_samples)
    
    # 保存混合后的测试集
    output_file = os.path.join('IdeaB', 'data', 'test', 'mixed_testset.json')
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(all_samples, f, indent=4, ensure_ascii=False)
    
    print(f"混合测试集已保存到: {output_file}")
    print(f"总样本数: {len(all_samples)}")

if __name__ == "__main__":
    mix_testset()
