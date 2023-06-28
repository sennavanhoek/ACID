"""
This file "hides" most functions used in ACID to keep it more streamlined.
When tinkering with these functions it's best to move them to the relevant
jupyter notebook part. That way you have all the benefits of using a notebook
without having to scroll rough a wall of code all the time.
"""

import os
import pyhidra
import ipywidgets as widgets
import plotly.express as px
import plotly.graph_objects as go
from tqdm.notebook import tqdm
from traitlets import directional_link


###############################################################################
# Select functions
###############################################################################


def get_isa_representarion(codeUnit):
    """
    Converts a Ghidra codeunit containing an LSU instruction into
    the ARMv7-M ISA representation of that instruction.

            Parameters:
                    codeUnit (codeUnit): A Ghidra codeunit

            Returns:
                    prototype (str): ARMv7-M ISA representation of instruction
                    scalar (int): Scalar used in instruction
    """
    scalar, neg_scalar, in_ref = 0, False, False
    reg_count = 1
    prototype = f"{codeUnit.getMnemonicString().upper()} "
    ops = ""
    for i in range(codeUnit.getNumOperands()):
        op = ""
        for op_part in codeUnit.getDefaultOperandRepresentationList(i):
            opstr = str(type(op_part)).split("'")[1].split(".")[-1]
            if opstr == "Scalar":
                scalar = int(str(op_part), 16)
                scalar *= -1 if neg_scalar else 1
            if opstr == "Character":
                if str(op_part) == "-":
                    neg_scalar = True
                else:
                    if str(op_part) == "[":
                        in_ref = True
                        reg_count = 1
                    op += str(op_part)
            elif opstr == "Register":
                if reg_count > 2:
                    op += f"Rx{reg_count}"
                elif in_ref:
                    op += "Rn" if reg_count == 1 else "Rm"
                else:
                    op += "Rt" if reg_count == 1 else "Rt2"
                reg_count += 1
            else:
                op += "offset" if opstr == "Scalar" else opstr
        ops += op.replace("[GenericAddress]", "label")
        if i < codeUnit.getNumOperands() - 1:
            ops += ","
    if ops == "Rt,Rt2,Rx3,offset":
        ops = "Rt,[Rn,Rm,LSL #n]"
    elif ops == "Rt,Rt2,Rx3":
        ops = "Rt,[Rn,Rm]"
    elif ",#offset" in ops and scalar == 0:
        ops = ops.replace(",#offset", "")
    prototype += ops.replace(",", ", ")
    return prototype, scalar


def analyze_file(file_path):
    """
    Automatically analyze a binary file using Ghidra, extracting the information needed for further steps.

            Parameters:
                    file_path (str): The path of the file that will be analyzed

            Returns:
                    info_dict (dict): A dictionary containing information about analyzed functions and thier relations
    """
    functions = {}
    with pyhidra.open_program(file_path) as flat_api:
        currentProgram = flat_api.getCurrentProgram()
        if str(currentProgram.getLanguage().getProcessor()) != "ARM":
            return False
        listing = currentProgram.getListing()
        fm = currentProgram.getFunctionManager()
        funcs = list(fm.getFunctions(True))
        links = ([], [])
        for func in funcs:
            function = {
                "name": func.getName(),
                "called_by": [],
                "calls": [],
                "instructions": [],
                "isa_reps": [],
                "scalars": [],
                "addresses": [],
            }
            functions[f"{func.getName()} @ 0x{func.getEntryPoint()}"] = function
        fids = list(functions.keys())
        for func in funcs:
            fid = f"{func.getName()} @ 0x{func.getEntryPoint()}"
            entry_point = func.getEntryPoint()
            references = flat_api.getReferencesTo(entry_point)
            for xref in references:
                if fm.getFunctionContaining(xref.fromAddress):
                    fr_fun = fm.getFunctionContaining(xref.fromAddress)
                    fromaddr = f"{fr_fun.getName()} @ 0x{xref.fromAddress}"
                    frid = f"{fr_fun.getName()} @ 0x{fr_fun.getEntryPoint()}"
                    if fid not in functions[frid]["calls"]:
                        functions[frid]["calls"].append(fid)
                        if not frid.startswith("_") and not fid.startswith("_"):
                            links[0].append(fids.index(frid))
                            links[1].append(fids.index(fid))
                else:
                    fromaddr = str(xref.fromAddress)
                functions[fid]["called_by"].append(fromaddr)
            for codeUnit in listing.getCodeUnits(func.getBody(), True):
                mnemonic = codeUnit.getMnemonicString().upper()
                if codeUnit.getMnemonicString() != "??":
                    functions[fid]["instructions"].append(str(codeUnit))
                    functions[fid]["addresses"].append(codeUnit.getAddress())
                    if mnemonic.startswith("LDR") or mnemonic.startswith("STR"):
                        inst, scalar = get_isa_representarion(codeUnit)
                        functions[fid]["isa_reps"].append(inst)
                        functions[fid]["scalars"].append(scalar)
                    else:
                        functions[fid]["isa_reps"].append("OTHER")
                        functions[fid]["scalars"].append(0)
    info_dict = {"functions": functions, "call_graph": links}
    return info_dict


def files(path):
    """
    A simple generator function to get the files from a folder.

            Parameters:
                    path (str): The path of the folder

            Yields:
                    file (str): A filename
    """
    for file in os.listdir(path):
        if os.path.isfile(os.path.join(path, file)):
            yield file


def callgraph(filename, files_analyzed):
    """
    Shows a call graph for a given file.

        Parameters:
                filename (str): The name of the selected file
                files_analyzed (dict): The collected info about all files
    """
    names = list(files_analyzed[filename]["functions"].keys())
    source = files_analyzed[filename]["call_graph"][0]
    target = files_analyzed[filename]["call_graph"][1]
    label = [n.split(" ")[0] for n in names]
    fig = sankey(source, target, label)
    fig.show()


def sankey(source, target, label):
    """
    Builds a sankey plot.

            Parameters:
                    source (list): A list of staring nodes
                    target (list): A list of end nodes

            Returns:
                    fig (figure): The generated sankey plot
    """
    fig = go.Figure(
        data=[
            go.Sankey(
                node=dict(pad=10, line=dict(color="black", width=1), label=label),
                link=dict(source=source, target=target, value=[1] * len(source)),
            )
        ]
    )
    fig.update_layout(font_size=12, height=800)
    return fig


def link_btns(tab_nest):
    """
    Creates a directional link between buttons to enable "select all called functions" functionality.

            Parameters:
                    tab_nest (widget): The collection of widget elements for the function selector
    """
    function_btns = {}
    for i, file in enumerate(tab_nest.children):
        function_btns[tab_nest.titles[i]] = {}
        for fsc in file.children:
            if hasattr(fsc.children[0], "children"):
                for fscc in fsc.children[0].children:
                    function_btns[tab_nest.titles[i]][
                        fscc.children[0].description
                    ] = fscc.children[0]
            else:
                if hasattr(fsc.children[0], "description"):
                    function_btns[tab_nest.titles[i]][
                        fsc.children[0].description
                    ] = fsc.children[0]
    for i, file in enumerate(tab_nest.children):
        for fsc in file.children:
            if hasattr(fsc.children[0], "children"):
                for fscc in fsc.children[0].children:
                    if len(fscc.children) > 1:
                        for btn in fscc.children[1].tooltip.split("\n"):
                            directional_link(
                                (fscc.children[1], "value"),
                                (function_btns[tab_nest.titles[i]][btn], "value"),
                            )
            else:
                if len(fsc.children) > 1:
                    for btn in fsc.children[1].tooltip.split("\n"):
                        directional_link(
                            (fsc.children[1], "value"),
                            (function_btns[tab_nest.titles[i]][btn], "value"),
                        )


def get_function_selector(file, files_analyzed):
    """
    Builds the function selector widget for a specific file.

            Parameters:
                    file (str): The name of the file
                    files_analyzed (dict): A dictionary of information about the target files

            Returns:
                    selector (widget): The function selector widget for a given file
    """
    functions = files_analyzed[file]["functions"]
    f_cat = {}
    for fk in functions.keys():
        cat = fk.split("_")[0]
        cat = "_" if cat == "" else cat
        if cat in f_cat:
            f_cat[cat][fk] = functions[fk]
        else:
            f_cat[cat] = {fk: functions[fk]}
    v_items = []
    catch = widgets.Output()
    with catch:
        callgraph(file, files_analyzed)
    v_items.append(
        widgets.Accordion(children=[catch], titles=(("Simplified Call Graph",)))
    )
    for fk in f_cat.keys():
        items = []
        for f in f_cat[fk].keys():
            called_by = "\n\t".join(f_cat[fk][f]["called_by"])
            calls = "\n\t".join(f_cat[fk][f]["calls"])
            tb = widgets.ToggleButton(
                value=False,
                description=f,
                disabled=False,
                button_style="info",
                tooltip=f"Is called by:\n\t{called_by}\nCalls:\n\t{calls}",
                icon="",
                layout=widgets.Layout(width="60%", height="35px"),
            )
            if calls != "":
                tb2 = widgets.ToggleButton(
                    description="Select all called functions",
                    tooltip=calls.replace("\t", ""),
                    layout=widgets.Layout(width="39%", height="35px"),
                )
                items.append(widgets.HBox([tb, tb2]))
            else:
                items.append(widgets.HBox([tb]))
        if len(items) > 1:
            v_items.append(
                widgets.Accordion(children=[widgets.VBox(items)], titles=((fk,)))
            )
        else:
            v_items.append(items[0])
    selector = widgets.VBox(v_items, layout=widgets.Layout(width="95%"))
    return selector


def build_function_selector(files_analyzed):
    """
    Builds the function selector widget.

            Parameters:
                    files_analyzed (dict): A dictionary of information about the target files

            Returns:
                    function_selector (widget): The complete function selector widget
    """
    function_selector = widgets.Tab()
    function_selector.children = [
        get_function_selector(key, files_analyzed)
        for key in tqdm(files_analyzed.keys(), desc="Building Selector")
    ]
    function_selector.titles = tuple(files_analyzed.keys())
    link_btns(function_selector)
    return function_selector


###############################################################################
# Settings
###############################################################################


def get_selected_functions(function_selector):
    """
    returns a dictionary with the selected functions for every file.

            Parameters:
                    function_selector (widget): The function selector widget

            Returns:
                    selected_functions (dict): The selected functions indexed by file
    """
    selected_functions = {}
    for i, file in enumerate(function_selector.children):
        selected_functions[function_selector.titles[i]] = []
        for fsc in file.children:
            if hasattr(fsc.children[0], "children"):
                for fscc in fsc.children[0].children:
                    if fscc.children[0].value:
                        selected_functions[function_selector.titles[i]].append(
                            fscc.children[0].description
                        )
            else:
                if hasattr(fsc.children[0], "value"):
                    if fsc.children[0].value:
                        selected_functions[function_selector.titles[i]].append(
                            fsc.children[0].description
                        )
    return selected_functions


def collect_label_sets(files_analyzed, selected_functions):
    """
    Returns the unique labels for all files combined and for every file individually.
    Here the labels are the isa representations of instructions, but this can be changed.

            Parameters:
                    files_analyzed (dict): A dictionary of information about the target files
                    selected_functions (dict): The selected functions indexed by file

            Returns:
                    label_set (list): Unique labels for all files combined
                    file_label_sets (dict): Unique labels for every file indexed by file
    """
    label_set = []
    file_label_sets = {}
    label_type = "isa_reps"
    for file in selected_functions.keys():
        labels = []
        for function in selected_functions[file]:
            labels.extend(files_analyzed[file]["functions"][function][label_type])
        file_label_sets[file] = sorted(set(labels))
        label_set = sorted(set(labels + label_set))
    if label_set == []:
        for file in files_analyzed.keys():
            labels = []
            for function in files_analyzed[file]["functions"]:
                selected_functions[file].append(function)
                labels.extend(files_analyzed[file]["functions"][function][label_type])
            file_label_sets[file] = sorted(set(labels))
            label_set = sorted(set(labels + label_set))
    return label_set, file_label_sets


def get_settings_selector(label_set):
    """
    Generates the settings selector widget.

            Parameters:
                    label_set (list): Unique labels for all files combined

            Returns:
                    settings_selector (widget): The settings selector widget
    """
    out = []
    if label_set:
        page = []
        page.append(widgets.Label(value="Pattern Length:"))
        page.append(
            widgets.IntSlider(
                value=3,
                min=2,
                max=6,
                step=1,
                description="",
                readout=True,
                readout_format="d",
            )
        )
        page.append(
            widgets.Label(value="Amount of selected instructions starting pattern:")
        )
        page.append(
            widgets.IntSlider(
                value=3,
                min=0,
                max=6,
                step=1,
                description="",
                readout=True,
                readout_format="d",
            )
        )
        page.append(widgets.Label(value="Select instruction types:"))
        items = []
        for label in label_set:
            if label != "OTHER":
                items.append(
                    widgets.ToggleButton(
                        description=label,
                        layout=widgets.Layout(width="90%", height="35px"),
                    )
                )
        page.append(
            widgets.GridBox(
                items, layout=widgets.Layout(grid_template_columns="repeat(5, 220px)")
            )
        )
        out.append(widgets.VBox(page))
    if out == []:
        out.append(widgets.Label(value="No selected functions"))
    settings_selector = widgets.Tab(children=out)
    settings_selector.titles = ("Settings",)
    return settings_selector


###############################################################################
# Show analysis
###############################################################################


def get_settings(settings_selector):
    """
    Returns a dictionary containing the settings configured in the settings selector.

            Parameters:
                    settings_selector (widget): The settings selector widget

            Returns:
                    settings (dict): A dictionary containing the settings configured in the settings selector
    """
    tab = settings_selector.children[0]
    settings = {}
    parts = tab.children
    settings["pattern_length"] = parts[1].value
    settings["sel_in_pattern"] = parts[3].value
    settings["selected_label"] = []
    for btn in parts[5].children:
        if btn.value:
            settings["selected_label"].append(btn.description)
    return settings


def heatmap(heatmp, file_label_set):
    """
    Returns a heat map generated from the heatmp 2d list.

            Parameters:
                    heatmp (list): a 2d list representing a heat map
                    file_label_set (list): Unique labels for the file

            Returns:
                    fig (figure): A heat map figure generated from the heatmp 2d list
    """
    ind = file_label_set.index("OTHER")
    heatmp.pop(ind)
    for i in heatmp:
        i.pop(ind)
    file_set = file_label_set.copy()
    file_set.pop(ind)
    fig = px.imshow(
        heatmp,
        labels=dict(x="inst 1", y="inst 2", color="Count"),
        x=file_set,
        y=file_set,
        title="Memory Instruction combinations in selected functions:",
    )
    size = 800
    if len(file_set) > 35:
        size += 150
    if len(file_set) > 60:
        size += 250
    fig.update_layout(
        title_y=1,
        xaxis={"tickangle": -50},
        width=size,
        height=size,
        margin=dict(l=150, r=150, b=100, t=100),
        xaxis_title=None,
        yaxis_title=None,
    )
    fig.update_xaxes(side="top")
    return fig


def analyze_instructions(selected_functions, functions, settings, file_label_set):
    """
    Finds all instruction patterns in the selected functions for a file.

            Parameters:
                    selected_functions (list): The selected functions for a file
                    functions (dict): Information about all functions in a file
                    settings (list): A dictionary containing the settings configured in the settings selector
                    file_label_set: All unique labels in all functions for that file

            Returns:
                    pattern_dict (dict): A dictionary containing the patterns structured to make a parcats figure
                    hm (fig): A heatmap figure 
                    patterns (list): A list of all patterns
    """
    pattern_length = settings["pattern_length"]
    sel_in_pattern = settings["sel_in_pattern"]
    pattern_dict = {}
    patterns = []
    offsets = []
    doffsets = []
    ns = []
    heatmp = [
        [0 for i in range(len(file_label_set))] for j in range(len(file_label_set))
    ]
    for function in selected_functions:
        labels = functions[function]["isa_reps"]
        scalars = functions[function]["scalars"]
        for i_hm in range(len(labels[:-1])):
            heatmp[file_label_set.index(labels[i_hm + 1])][
                file_label_set.index(labels[i_hm])
            ] += 1
        for i in range(len(labels) - pattern_length):
            select = True
            for offset in range(sel_in_pattern):
                select = select and labels[i + offset] != "OTHER"
            if select:
                if labels[i] not in pattern_dict.keys():
                    pattern_dict[labels[i]] = []
                pattern_dict[labels[i]].append(
                    [labels[i + j] for j in range(1, pattern_length)]
                )
                pattern = []
                for offset in range(pattern_length):
                    pattern.append(labels[i + offset])
                    if "#offset" in labels[i + offset]:
                        if "RD" in labels[i + offset]:
                            doffsets.append(scalars[i + offset])
                        else:
                            offsets.append(scalars[i + offset])
                    elif "#n" in labels[i + offset]:
                        ns.append(scalars[i + offset])
                if pattern not in patterns:
                    patterns.append(pattern)
    hm = heatmap(heatmp, file_label_set)
    return pattern_dict, hm, patterns


def build_parcats(pattern_dict, settings):
    """
    Displays a parallel categories diagram

            Parameters:
                    pattern_dict (dict): A dictionary containing the label patterns
                    settings (list): A dictionary containing the settings configured in the settings selector

            Returns:
                    fig (figure): The parallel categories diagram
    """
    if len(pattern_dict) == 0:
        print("Not enough instructions to plot parallel categories diagram.")
        return
    dim = []
    for i in range(settings["pattern_length"]):
        dim.append({"label": "", "values": []})
    for k in sorted(pattern_dict.keys()):
        for val in pattern_dict[k]:
            for i in range(settings["pattern_length"]):
                v = k if i == 0 else val[i - 1]
                dim[i]["values"].append(v)
    color = []
    for v in dim[0]["values"]:
        color.append(sorted(pattern_dict.keys()).index(v))
    colorscale = []
    for i in range(len(pattern_dict.keys())):
        colorscale.append(
            [1, (px.colors.qualitative.Dark24 + px.colors.qualitative.Light24)[i % 48]]
        )
    fig = go.Figure(
        go.Parcats(dimensions=dim, line={"color": color, "colorscale": colorscale})
    )
    fig.update_layout(
        font=dict(size=17),
        width=1200,
        height=800,
        margin=dict(l=150, r=150, b=100, t=100, pad=40),
        title="Instruction patterns in selected functions:",
    )
    fig.show()


def generate_report(selected_functions, files_analyzed, file_label_sets, settings):
    """
    Generates the report widget containing the graphs for every file

            Parameters:
                    selected_functions (dict): The selected functions indexed by file
                    files_analyzed (dict): A dictionary of information about the target files
                    file_label_sets (dict): The unique labels for every file indexed by file
                    settings (list): A dictionary containing the settings configured in the settings selector

            Returns:
                    report (widget): The report widget containing the graphs for every file
    """
    pattern_dict = {}
    order_dict = {}
    heatmp_dict = {}
    for file in selected_functions.keys():
        sel_funcs = selected_functions[file]
        if sel_funcs:
            funcs = files_analyzed[file]["functions"]
            (
                order_dict[file],
                heatmp_dict[file],
                pattern_dict[file],
            ) = analyze_instructions(sel_funcs, funcs, settings, file_label_sets[file])

    out = []
    data = []
    tabs = tuple(order_dict.keys())

    for k in order_dict.keys():
        out.append(widgets.Output())
        data.append(order_dict[k])
    for i, k in enumerate(order_dict.keys()):
        with out[i]:
            build_parcats(order_dict[k], settings)
            heatmp_dict[k].show()
    report = widgets.Tab(children=out)
    report.titles = tabs
    return report