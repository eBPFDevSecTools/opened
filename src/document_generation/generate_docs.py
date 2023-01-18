#Extracted from https://github.com/Brown-NSG/opened/blob/main/documentation_generation/generate_docs.py

#!/usr/bin/env python3

from os import getenv, listdir
from os.path import isfile, join
import sys
import openai
import time
from tenacity import (
    retry,
    stop_after_attempt,
    wait_random_exponential,
)

# Must pass source directory as arugment
if len(sys.argv) != 2:
    print("Please pass the source directory as an argument to this script.")
    print('Usage: ./generate_docs.py <dir containing .xml files>')
    sys.exit(1)

# Must set the OPENAI_API_KEY environment variable
if getenv("OPENAI_API_KEY") is None:
    print("Please set the OPENAI_API_KEY environment variable to your OpenAI API key.")
    print('As an example, you could try:')
    print('export OPENAI_API_KEY="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"')
    print('To solve this problem permanently, you can add above line to the ~/.bashrc file.')
    sys.exit(1)

# Get OpenAI API key from env variable
openai.api_key = getenv("OPENAI_API_KEY")

# Get the source folder containing the extracted functions
src_dir = sys.argv[1]

# Collect the .xml files in the source folder
xml_files = [join(src_dir, f) for f in listdir(src_dir) if isfile(join(src_dir, f)) and f.endswith('.xml')]

# Collect the functions in each XML file
functions = []
for file in xml_files:
    with open(file,'r', encoding='utf-8') as f:
        data = f.read()
        source = data.find('<source')
        while source != -1:
            start = data.find('>', source) + 1
            end = data.find('</source>', start)
            functions.append(data[start:end])
            data = data[end+9:]
            source = data.find('<source')

# Exponential backoff for OpenAI API requests
@retry(wait=wait_random_exponential(min=1, max=60), stop=stop_after_attempt(6))
def completion_with_backoff(**kwargs):
    return openai.Completion.create(**kwargs)

# Map functions to their extracted function prompts
stop = "\"\"\""
prompt = '\n' + stop + '\nSummary of the above code:\n'
prompts = list(map(lambda s: s + prompt, functions))

# Call the OpenAI API to generate a code explanation for each function
count = 1
output = open(join(src_dir, "functions-with-docs.txt"), "w")
for p in prompts:
    response = completion_with_backoff(model="code-davinci-002", prompt=p, temperature=0, max_tokens=1000, top_p=1, frequency_penalty=1, presence_penalty=0, stop=[stop])

    print("Generated doc for function " + str(count))
    count += 1

    output.write(p + "\n")
    output.write(response.choices[0].text + "\n\n")

output.close()
