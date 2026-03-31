import json
import os
import random

def mix_knowledge():
    """混合所有CWE的知识库，打乱顺序"""
    
    # CWE列表
    cwe_list = ['119', '125', '200', '20', '264', '362', '401', '416', '476', '787']
    
    all_knowledge = []
    
    # 读取每个CWE的知识文件
    for cwe in cwe_list:
        filename = f'linux_kernel_CWE-{cwe}_knowledge.json'
        filepath = os.path.join('src', 'output', 'knowledge', 'baseline_knowledge', filename)
        
        if not os.path.exists(filepath):
            print(f"警告: 文件不存在: {filepath}")
            continue
        
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # 添加CWE信息
        for item in data:
            item['cwe_id'] = f'CWE-{cwe}'
            all_knowledge.append(item)
    
    # 打乱顺序
    random.shuffle(all_knowledge)
    
    # 保存混合后的知识库
    output_file = os.path.join('IdeaB', 'data', 'knowledge', 'mixed_knowledge.json')
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(all_knowledge, f, indent=4, ensure_ascii=False)
    
    print(f"混合知识库已保存到: {output_file}")
    print(f"总知识条目数: {len(all_knowledge)}")

if __name__ == "__main__":
    mix_knowledge()
