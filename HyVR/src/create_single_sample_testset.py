#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
创建只包含一个样本的测试集，用于测试流程
"""

import json
import os

def create_single_sample_testset():
    """从混合测试集中提取第一个样本，创建单独的测试文件"""
    
    # 读取混合测试集
    mixed_testset_path = os.path.join('IdeaB', 'data', 'test', 'mixed_testset.json')
    
    if not os.path.exists(mixed_testset_path):
        print(f"错误: 混合测试集文件不存在: {mixed_testset_path}")
        print("请先运行: python IdeaB/src/preprocess/mix_testset.py")
        return
    
    with open(mixed_testset_path, 'r', encoding='utf-8') as f:
        all_samples = json.load(f)
    
    if not all_samples:
        print("错误: 混合测试集为空")
        return
    
    # 提取第一个样本
    single_sample = [all_samples[0]]
    
    # 保存为单独的测试文件
    output_path = os.path.join('IdeaB', 'data', 'test', 'single_sample_testset.json')
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(single_sample, f, indent=4, ensure_ascii=False)
    
    print(f"单样本测试集已创建: {output_path}")
    print(f"样本ID: {single_sample[0]['id']}")
    print(f"原始CWE: {single_sample[0]['original_cwe']}")
    print("\n样本信息:")
    print(f"ID: {single_sample[0]['id']}")
    print(f"CVE ID: {single_sample[0]['cve_id']}")
    print(f"原始CWE: {single_sample[0]['original_cwe']}")
    print(f"代码长度: {len(single_sample[0]['code_before_change'])} 字符")

if __name__ == "__main__":
    create_single_sample_testset()
