# Create this test file to debug the asyncio issue
# Save as: test_asyncio_debug.py

import asyncio

async def test_asyncio_execution():
    """Test to debug the asyncio execution issue"""
    
    # This is similar to what your AI generates
    ai_generated_code = """
async def analyze_security_threats(target_data: dict, sensor: object) -> dict:
    return {
        'risk_score': 0.8,
        'threats_found': ['test_threat'],
        'evidence': ['This is a test'],
        'user_explanation': 'Test analysis complete'
    }
"""
    
    # Test the broken approach (what you currently have)
    print("=== TESTING BROKEN APPROACH ===")
    execution_globals = {
        '__builtins__': __builtins__,
        'asyncio': asyncio,
    }
    execution_locals = {}
    
    broken_execution_code = f"""{ai_generated_code}

# This is the BROKEN approach
result = asyncio.create_task(analyze_security_threats({{}}, None))
"""
    
    try:
        exec(broken_execution_code, execution_globals, execution_locals)
        print("Code executed successfully")
        print(f"Result found in locals: {'result' in execution_locals}")
        print(f"Result type: {type(execution_locals.get('result', 'NOT_FOUND'))}")
        if 'result' in execution_locals:
            task = execution_locals['result']
            print(f"Task done: {task.done()}")
            print(f"Task result: {task.result() if task.done() else 'NOT_DONE'}")
    except Exception as e:
        print(f"Execution error: {e}")
    
    print("\n=== TESTING FIXED APPROACH ===")
    execution_globals2 = {
        '__builtins__': __builtins__,
        'asyncio': asyncio,
    }
    execution_locals2 = {}
    
    # This is the FIXED approach
    fixed_execution_code = f"""{ai_generated_code}

# This is the FIXED approach
async def _execute_analysis():
    return await analyze_security_threats({{}}, None)

# Store the coroutine for later execution
_analysis_coro = _execute_analysis()
"""
    
    try:
        exec(fixed_execution_code, execution_globals2, execution_locals2)
        print("Code executed successfully")
        print(f"Coroutine found in locals: {'_analysis_coro' in execution_locals2}")
        
        if '_analysis_coro' in execution_locals2:
            coro = execution_locals2['_analysis_coro']
            print(f"Coroutine type: {type(coro)}")
            
            # Now await the coroutine
            result = await coro
            print(f"Final result: {result}")
            print(f"Risk score: {result.get('risk_score')}")
            
    except Exception as e:
        print(f"Execution error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_asyncio_execution())
    