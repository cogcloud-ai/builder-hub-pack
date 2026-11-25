"""Render trusted Studio assets while treating workspace HTML as untrusted data."""
import re


def metadata(html):
    tokens = re.findall(r'<meta name="cog-workbench-token" content="([A-Za-z0-9_-]{16,128})">', html)
    qualified = re.findall(r'<meta name="builder-execution-qualified" content="(true|false)">', html)
    if len(tokens) != 1 or len(qualified) != 1:
        raise ValueError('Workspace page metadata is missing or ambiguous.')
    return tokens[0], qualified[0] == 'true'


def render(template, token, qualified):
    if not re.fullmatch(r'[A-Za-z0-9_-]{16,128}', token):
        raise ValueError('Invalid workspace page token.')
    page = template.replace("token='__SUITE_TOKEN__'", 'token=document.querySelector(\'meta[name="cog-workbench-token"]\').content')
    tags = ('<meta name="cog-workbench-token" content="' + token + '">'
            '<meta name="builder-execution-qualified" content="' + ('true' if qualified else 'false') + '">')
    page = page.replace('</title>', '</title>' + tags, 1)
    page = page.replace('<a href="/">Inspect a Cog →</a>', '<a href="/web/home">Back to Collab Hub →</a>')
    availability = ('Generated-code verification uses an isolated container with no network.' if qualified
                    else 'Generated-code verification is awaiting isolation qualification.')
    note = ('<section class="card"><h2>Your private Builder workspace</h2>'
            '<p>Design, author and package Cogs. Saved builds and evidence stay in this workspace. '
            + availability + '</p><button id="hostedSmoke">Run integration check</button>'
            '<p id="hostedResult" role="status"></p></section>')
    page = page.replace('<main>', '<main>' + note)
    policy = """
const hostedBlocked = new Set(['gateway','cases',__BLOCKED_BUILD__]);
function hostedControls(){for(const id of hostedBlocked){const e=$(id);if(e){e.disabled=true;e.title='Use saved builds for isolated verification.'}}for(const e of document.querySelectorAll('[data-check]'))if(e.dataset.check!=='check'){e.disabled=true;e.title='Use saved builds for isolated verification.'}}
const originalControls=controls; controls=function(){originalControls();hostedControls()};
const originalBuildControls=buildControls; buildControls=function(){originalBuildControls();hostedControls()};
$('hostedSmoke').onclick=handle(async()=>{let value=await job({action:'smoke-fixture'});$('hostedResult').textContent='Integration check passed. Word totals '+value.outputs.first_tally.total_words+' and '+value.outputs.accumulated_tally.total_words+'. Evidence saved.'});
hostedControls();
$('model').value='sonnet'; $('model').readOnly=true;
$('decisionBy').value='Your signed-in Hub account'; $('decisionBy').readOnly=true;
$('buildAttempts').max='5'; $('buildCost').max='30';
for(const id of ['upstream','modelBinding','gateway']){const el=$(id);if(el)el.hidden=true;const label=document.querySelector('label[for="'+id+'"]');if(label)label.hidden=true}
$('connect').closest('section').querySelector('p').textContent='Use the Claude subscription configured for this workspace. Credentials stay with its vendor login store.';
"""
    policy = policy.replace('__BLOCKED_BUILD__', '' if qualified else "'acceptBuild','resumeBuild'")
    return page.replace('</script>', policy + '</script>')
