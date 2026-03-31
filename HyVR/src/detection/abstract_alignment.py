import json
import os
import sys

# 添加项目根目录到路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

import utils.llm_client as llm_client

class AbstractAlignment:
    """抽象对齐模块，用于将代码行为模式与原则库的漏洞行为模式进行匹配"""
    
    def __init__(self, principle_knowledge_file):
        """初始化抽象对齐模块"""
        self.principle_knowledge_file = principle_knowledge_file
        self.principle_knowledge = None
        self.llm_client = None
        
        # 加载原则库
        self.load_principle_knowledge()
    
    def load_principle_knowledge(self):
        """加载原则库"""
        if os.path.exists(self.principle_knowledge_file):
            with open(self.principle_knowledge_file, 'r', encoding='utf-8') as f:
                self.principle_knowledge = json.load(f)
            print(f"加载了 {len(self.principle_knowledge)} 条原则知识")
        else:
            print(f"原则库文件不存在: {self.principle_knowledge_file}")
            self.principle_knowledge = []
    
    def initialize_llm(self, model_name):
        """初始化LLM客户端"""
        self.llm_client = llm_client.get_llm_client(model_name)
        print(f"使用模型: {self.llm_client.model_name}")
    
    def extract_code_behavior_pattern(self, code_snippet, purpose, function):
        """使用LLM提取代码的行为模式"""
        prompt = f"""Analyze the following code snippet and extract its behavior patterns. Focus on identifying vulnerability-related behaviors that could indicate security issues.

Code Snippet:
'''
{code_snippet}
'''

Code Purpose: {purpose}
Code Functions: {function}

Please describe the behavior patterns in a concise way, focusing on potential security-related behaviors. Output only the description without any additional explanation.
"""
        
        prompt_dict = llm_client.generate_simple_prompt(prompt)
        output = self.llm_client.generate_text(prompt_dict, {})
        
        return output.strip()
    
    def align_with_principles(self, code_behavior_pattern, top_k=3):
        """将代码行为模式与原则库进行对齐"""
        if not self.principle_knowledge:
            return []
        
        print("使用大模型计算代码行为模式与原则库的相似度...")
        
        alignment_results = []
        total_principles = len(self.principle_knowledge)
        
        for i, principle in enumerate(self.principle_knowledge):
            cwe_id = principle.get('cwe_id', 'Unknown')
            common_code_behavior = principle.get('common_code_behavior', '')
            
            print(f"正在对齐第 {i+1}/{total_principles} 条原则: {cwe_id}")
            
            # 使用LLM计算相似度
            prompt = f"""Compare the following two code behavior patterns and determine their similarity for vulnerability detection.

Code Behavior Pattern:
{code_behavior_pattern}

Principle Common Code Behavior:
{common_code_behavior}

Please analyze how similar these two behavior patterns are in the context of vulnerability detection. Consider:
1. The semantic similarity of the behaviors
2. The relevance to the specific vulnerability type ({cwe_id})
3. The likelihood that the code exhibits characteristics of this vulnerability type

Provide a similarity score between 0 and 1, where 1 means very similar and 0 means not similar at all. Output only the score without any explanation."""
            
            prompt_dict = llm_client.generate_simple_prompt(prompt)
            output = self.llm_client.generate_text(prompt_dict, {})
            
            # 解析相似度分数
            try:
                score = float(output.strip())
                alignment_results.append({
                    'principle': principle,
                    'similarity_score': score
                })
                print(f"对齐完成: {cwe_id}, 相似度: {score}")
            except Exception as e:
                print(f"对齐失败: {cwe_id}, 错误: {str(e)}")
                continue
        
        # 按相似度排序并返回前k个
        alignment_results.sort(key=lambda x: x['similarity_score'], reverse=True)
        print(f"对齐完成，共找到 {len(alignment_results)} 条匹配的原则")
        return alignment_results[:top_k]

    def retrieve_principle_knowledge(self, code_snippet, purpose, function, top_k=3):
        """检索相关的原则知识"""
        if not self.llm_client:
            print("LLM客户端未初始化")
            return []
        
        # 提取代码行为模式
        code_behavior_pattern = self.extract_code_behavior_pattern(code_snippet, purpose, function)
        print(f"代码行为模式: {code_behavior_pattern}")
        
        # 与原则库对齐
        aligned_principles = self.align_with_principles(code_behavior_pattern, top_k)
        
        # 返回对齐结果
        return aligned_principles

if __name__ == "__main__":
    # 测试抽象对齐模块
    aligner = AbstractAlignment('src/output/knowledge/principle_knowledge_new_format/cwe_CWE_401_principle_knowledge.json')
    aligner.initialize_llm('qwen2.5-coder:14b')
    
    # 测试代码
    test_code = """
    void func() {
        char *buf = malloc(100);
        if (!buf)
            return;
        // 使用buf
        if (error_condition)
            return; // 内存泄漏
        free(buf);
    }
    """
    
    results = aligner.retrieve_principle_knowledge(test_code, "内存分配和释放", "分配内存、使用内存、释放内存")
    print(f"对齐结果: {len(results)}")
    for i, result in enumerate(results):
        print(f"{i+1}. CWE: {result['principle']['cwe_id']}, 相似度: {result['similarity_score']}")
