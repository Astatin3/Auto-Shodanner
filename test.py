import src.utils as utils

def parse_csv_line(line):
    elements = []
    current_element = ""
    inside_array = False
    array_content = ""
    inside_quotes = False
    
    for char in line:
        if char == ',' and not inside_array and not inside_quotes:
            if array_content:
                elements.append(parse_csv_line(array_content[1:-1]))
                array_content = ""
            else:
                elements.append(current_element.strip())
            current_element = ""
        elif char == '[' and not inside_quotes:
            inside_array = True
            array_content += char
        elif char == ']' and not inside_quotes:
            inside_array = False
            array_content += char
        elif char == "'":
            inside_quotes = not inside_quotes
            current_element += char
        else:
            if inside_array:
                array_content += char
            else:
                current_element += char
    
    if current_element:
        if current_element.startswith("'") and current_element.endswith("'"):
            current_element = current_element[1:-1]
        elements.append(current_element.strip())
    elif array_content:
        elements.append(parse_csv_line(array_content[1:-1]))
    
    return elements


def find():
  # print("started!")
  for folder in utils.listSubdirs(utils.getRoot("data/scans/")):
    for file in utils.listSubdirs(utils.getRoot(f"data/scans/{folder}")):
      with open(utils.getRoot(f"data/scans/{folder}/{file}"), "r") as file:
        lines = file.readlines()
        for line in lines:
          data = parse_csv_line(line)
          if data[1] != "1":
            continue
          print(f'{data[0]} ({data[2]}), {data[4]}')
    
  # print("sotopped!!")