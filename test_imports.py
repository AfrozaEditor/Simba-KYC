import importlib

modules = [
    'aiohttp', 'numpy', 'cv2', 'PIL', 'zxingcpp',
    'pydantic', 'pydantic_settings', 'dotenv', 'boto3'
]

for module in modules:
    try:
        # Special case for dotenv as it is usually imported from 'python-dotenv' as 'dotenv'
        if module == 'dotenv':
            importlib.import_module('dotenv')
        elif module == 'PIL':
            importlib.import_module('PIL')
        else:
            importlib.import_module(module)
        print(f"{module}:OK")
    except ImportError as e:
        print(f"{module}:ERR:{e}")
    except Exception as e:
        print(f"{module}:ERR:{type(e).__name__}: {e}")
