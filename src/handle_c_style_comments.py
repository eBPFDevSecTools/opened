#COPIED from here: <script src="https://gist.github.com/ChunMinChang/88bfa5842396c1fbbc5b.js"></script>
#Copyright with authors mentioned at above link.
#!/usr/bin/python
import re
import sys

# finds a pattern in lines and return an array of  start line, end line and text of the
# non overlapping matches of the pattern
def find_c_style_comment_matches(data, comment_regex_pattern=r'//.*?$|/\*.*?\*/'):
    regex = re.compile(comment_regex_pattern, re.MULTILINE | re.DOTALL)
    matches = []
    for match in regex.finditer(data):
        start_line = data.count('\n', 0, match.start()) + 1
        end_line = data.count('\n', 0, match.end()) + 1
        matched_text = match.group()
        matches.append({
            'start_line': start_line,
            'end_line': end_line,
            'text': matched_text
        })
    return matches

def find_c_style_comment_matches_in_func(data, lineOffset):
    matches = find_c_style_comment_matches(data)
    for match in matches:
        match['start_line'] = match['start_line']+lineOffset
        match['end_line'] = match['end_line']+lineOffset
    return matches

def removeComments(text):
    """ remove c-style comments.
        text: blob of text with comments (can include newlines)
        returns: text with comments removed
    """
    c_style_comments_pattern_verbose = r"""
                            ##  --------- COMMENT ---------
           //.*?$           ##  Start of // .... comment
         |                  ##
           /\*              ##  Start of /* ... */ comment
           [^*]*\*+         ##  Non-* followed by 1-or-more *'s
           (                ##
             [^/*][^*]*\*+  ##
           )*               ##  0-or-more things which don't start with /
                            ##    but do end with '*'
           /                ##  End of /* ... */ comment
         |                  ##  -OR-  various things which aren't comments:
           (                ##
                            ##  ------ " ... " STRING ------
             "              ##  Start of " ... " string
             (              ##
               \\.          ##  Escaped char
             |              ##  -OR-
               [^"\\]       ##  Non "\ characters
             )*             ##
             "              ##  End of " ... " string
           |                ##  -OR-
                            ##
                            ##  ------ ' ... ' STRING ------
             '              ##  Start of ' ... ' string
             (              ##
               \\.          ##  Escaped char
             |              ##  -OR-
               [^'\\]       ##  Non '\ characters
             )*             ##
             '              ##  End of ' ... ' string
           |                ##  -OR-
                            ##
                            ##  ------ ANYTHING ELSE -------
             .              ##  Anything other char
             [^/"'\\]*      ##  Chars which doesn't start a comment, string
           )                ##    or escape
    """
    pattern = c_style_comments_pattern_verbose
    regex = re.compile(pattern, re.VERBOSE|re.MULTILINE|re.DOTALL)
    noncomments = [m.group(2) for m in regex.finditer(text) if m.group(2)]
    return "".join(noncomments)

def commentRemover(text):
    def replacer(match):
        s = match.group(0)
        if s.startswith('/'):
            return " " # note: a space and not an empty string
        else:
            return s
    c_style_comments_pattern = r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"'
    pattern = re.compile(c_style_comments_pattern, re.DOTALL | re.MULTILINE)
    return re.sub(pattern, replacer, text)


if __name__ == "__main__":
    filename = 'examples/xdp-mptm-main/src/kernel/mptm.c'
    with open(filename) as f:
        # uncmtFile = removeComments(f.read())
        human_comments = find_c_style_comment_matches(f.read())
        for comment in human_comments:
            print(comment)
        #uncmtFile = commentRemover(f.read())
        #print('uncmt file '+ str(uncmtFile))
