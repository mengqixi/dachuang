import os

def check_project_structure():
    expected_files = [
        'requirements.txt',
        'config/config.yaml',
        'config/logging.yaml',
        'src/encryption/paillier.py',
        'src/encryption/aby3_protocol.py',
        'src/detection/feature_extractor.py',
        'src/detection/attack_detector.py',
        'src/optimization/rl_optimizer.py',
        'src/optimization/environment_model.py',
        'src/federated/fate_client.py',
        'src/federated/pipeline_manager.py',
        'src/main.py',
        'docker/docker-compose.yml',
        'docker/Dockerfile',
        'tests/test_encryption.py',
        'tests/test_detection.py',
        'tests/test_optimization.py',
        'data/sample_training_data.csv',
        'README.md'
    ]
    
    print("=== 项目结构验证 ===")
    all_exists = True
    
    for file_path in expected_files:
        if os.path.exists(file_path):
            print(f"✓ {file_path}")
        else:
            print(f"✗ {file_path} - 缺失")
            all_exists = False
    
    if all_exists:
        print("\n✅ 所有文件已创建成功！")
    else:
        print("\n❌ 部分文件缺失")
    
    print("\n=== 项目目录结构 ===")
    for root, dirs, files in os.walk('.'):
        level = root.replace('.', '').count(os.sep)
        indent = ' ' * 2 * level
        print(f"{indent}{os.path.basename(root)}/")
        subindent = ' ' * 2 * (level + 1)
        for file in files[:5]:
            print(f"{subindent}{file}")
        if len(files) > 5:
            print(f"{subindent}... (共 {len(files)} 个文件)")

if __name__ == "__main__":
    check_project_structure()