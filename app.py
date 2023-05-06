from typing import Tuple

from flask import Flask, request, render_template
import os
import retroperm
from retroperm.project import RetropermProject
from retroperm.rules.filesystem_rule import FilesystemRule
from retroperm.rules.ban_category_rule import BanCategoryRule
from pathlib import Path
import ast
import re
import logging

logging.getLogger("cle").setLevel(logging.ERROR)

app = Flask(__name__)
# TEST_BINARIES = Path('/home/spyre/PycharmProjects/retroperm/tests/executables/')


def run_analysis(filepath: str, filename: str, rules: Tuple[bool, bool, bool, bool]):

    def eval_flow(proj, header):
        def iterprint(header: str, payload: dict) -> str:
            html_output = f"<h2>{header}</h2>"
            for key, v in payload.items():
                if v.startswith("Failed"):
                    html_output += f'<p style="color:red">{key}: {v}</p>'
                else:
                    html_output += f'<p style="color:green">{key}: {v}</p>'
            return html_output

        local_blob = ''
        # Rules
        # TODO: Fix directories in retroperm/ Check if they even work
        # Me from the future: They don't work
        rule_list = []
        ban_filesystem = BanCategoryRule('filesystem')
        ban_network = BanCategoryRule('network')
        tmp_rule = FilesystemRule("/tmp/", 'filename', is_whitelist=False, is_dir=True)
        etc_passwd = FilesystemRule("/etc/passwd", 'filename', is_whitelist=False, is_dir=False)
        # rule_list = [ban_filesystem, ban_network, tmp_rule, etc_passwd]

        if rules[0]:
            rule_list.append(ban_filesystem)
        if rules[1]:
            rule_list.append(ban_network)
        if rules[2]:
            rule_list.append(tmp_rule)
        if rules[3]:
            rule_list.append(etc_passwd)

        proj.init_rules(rule_list, override_default=True)

        proj.resolve_abusable_functions()

        val_rules = proj.validate_rules()
        print()
        # iterprint(header, val_rules)
        local_blob += iterprint(header, val_rules)

        print()
        if val_rules[ban_filesystem].startswith("Failed"):
            resolved_data = proj.resolve_abusable_functions()
            rfo = resolved_data['resolved_function_data']

            match_list = ast.literal_eval(re.findall(r'\[.*\]', val_rules[etc_passwd])[0])

            for match in match_list:
                if match not in rfo:
                    continue
                match_rfo = rfo[match]
                vals = list(match_rfo.args_by_location.values())
                print(str(vals))
                local_blob += f'<p style="color:blue">{str(vals)}</p>'

        return local_blob

    retro_proj = RetropermProject(filepath)

    blob = ''
    blob += eval_flow(retro_proj, f'{filename} Rule Validation')

    print(blob)
    return blob


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        filename = file.filename
        file.save(os.path.join('./temp', filename))
        rule_options = ('true' == request.form.get('option1'), 'true' == request.form.get('option2'),
                        'true' == request.form.get('option3'), 'true' == request.form.get('option4'))
        output = run_analysis(os.path.join('./temp', filename), filename, rule_options)
        # Delete file
        # os.remove(os.path.join('./temp', filename))
        return render_template('result.html', output=output)
    return render_template('upload.html')


if __name__ == '__main__':
    app.run(debug=True)
