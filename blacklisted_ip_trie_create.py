import os
import shutil

class TrieNode:
    def __init__(self):
        self.children = {}
        self.is_end_of_word = False

class Trie:
    def __init__(self):
        self.root = TrieNode()

    def insert(self, word):
        node = self.root
        for char in word:
            if char not in node.children:
                node.children[char] = TrieNode()
            node = node.children[char]
        node.is_end_of_word = True

    def search(self, word):
        node = self.root
        for char in word:
            if char not in node.children:
                return False
            node = node.children[char]
        return node.is_end_of_word

def clone_and_process_git_repo(repo_url="https://github.com/stamparm/ipsum", file_name="ipsum.txt"):
    # Clone the Git repository
    os.system(f'git clone {repo_url}')

    # Copy the specified file to the current directory
    shutil.copy(f'{os.path.basename(repo_url)}/{file_name}', file_name)

    # Read the IP addresses from the file and build a trie
    ip_trie = Trie()
    with open(file_name, 'r') as file:
        lines = file.readlines()[7:]  # Skip the first 5 lines
        for line in lines:
            
            ip, number_of_blacklists  = line.strip().split()
            # if "122.4.70.58	9" in line or "14.47.67.181" in line:
            #     print(line)
            #     print(ip)
            #     print(number_of_blacklists)
            #     print(number_of_blacklists.isnumeric())
            if isinstance(number_of_blacklists, str) and number_of_blacklists.isnumeric() and int(number_of_blacklists) > 0:
                ip_trie.insert(ip)
            elif isinstance(number_of_blacklists, int) and number_of_blacklists > 0:
                ip_trie.insert(ip)    
            else:
                continue

            

    # Delete the cloned Git repository
    shutil.rmtree(os.path.basename(repo_url))

    return ip_trie

# Example usage:
if __name__ == "__main__":
    repo_url = "https://github.com/stamparm/ipsum"
    file_name = "ipsum.txt"
    trie = clone_and_process_git_repo(repo_url, file_name)

    # Example IP address search
    ip_to_search = "122.4.70.58"
    if trie.search(ip_to_search):
        print(f"Found {ip_to_search} in the trie.")
    else:
        print(f"{ip_to_search} not found in the trie.")
