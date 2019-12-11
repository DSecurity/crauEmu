#
# Copyright (c) Digital Security. All rights reserved.
# Licensed under the MIT License. See LICENSE file in the project root for full license information.
#

from uEmu import *

CRAUEMU_USE_AS_SCRIPT = True    # Set to `False` if you want to load crauEmu automatically as IDA Plugin


from PyQt5.QtWidgets import (
    QStyledItemDelegate, QTableView, QWidget,
    QTextEdit, QTabWidget, QTabBar, QToolButton,
    QAbstractItemView, QAction, QLineEdit, QLabel,
    QVBoxLayout,
)

from PyQt5.QtCore import (
    Qt, QAbstractTableModel, QVariant, QModelIndex, pyqtSignal
)

from PyQt5.QtGui import QBrush, QColor

def crauemu_log(entry):
    uemu_log(entry, name = "crauEmu")


class uEmuRopTraceView(simplecustviewer_t):

    def __init__(self, owner):
        super(uEmuRopTraceView, self).__init__()
        self.owner = owner
        ue = owner.unicornEngine
        arch = UEMU_HELPERS.get_arch()
        _, self.uc_reg_sp = UEMU_HELPERS.get_stack_register(arch)
        self.uc_reg_pc = ue.uc_reg_pc

    def Create(self, title):
        if not simplecustviewer_t.Create(self, title):
            return False
        return True

    def SetContent(self, rop_tracer):
        self.ClearLines()
        self.AddLine(COLSTR('  [ Rop Tracer View ]', SCOLOR_AUTOCMT))
        self.AddLine('')
        if rop_tracer is None:
            return
        for line_addr, line_disas, line_changes in rop_tracer.get_trace():
            if len(line_changes) > 0:
                self.AddLine('%s: %s  %s' % (line_addr, COLSTR(line_disas, SCOLOR_INSN), COLSTR('# ' + line_changes, SCOLOR_DREF)))
            else:
                self.AddLine('%s: %s' % (line_addr, COLSTR(line_disas, SCOLOR_INSN)))

    def OnClose(self):
        self.owner.rop_trace_view_closed()

def parse_int(value, default=0):
    try:
        return int(value)
    except Exception as ex:
        pass
    try:
        return int(value, 16)
    except Exception as ex:
        pass
    return default

class RopModel(QAbstractTableModel):

    nameChanged = pyqtSignal()
    
    def __init__(self, name, addr, size, prev_size, values=[]):
        super(RopModel, self).__init__()
        self.name = name
        self.addr = addr
        self.init_addr = None
        self.size = size
        self.prev_size = prev_size
        self.values = values
        self.highlights = {}

    def rowCount(self, parent):
        return len(self.values) + 1

    def columnCount(self, parent):
        return 4
    
    def headerData(self, section, orientation, role):
        if role == Qt.DisplayRole:
            return ['Address', 'Value', 'Comments', 'Context'][section]

    def data(self, index, role):
        try:
            row = index.row()
            col = index.column()
            if role == Qt.DisplayRole:
                if row == len(self.values):
                    return QVariant()
                elif col == 0:
                    arch = UEMU_HELPERS.get_arch()
                    reg_bit_size = UEMU_HELPERS.get_register_bits(arch)
                    reg_byte_size = reg_bit_size // 8
                    if type(self.addr) in (str, unicode):
                        addr_str = '{}+{:x}'.format(self.addr,  row * reg_byte_size)
                    else:
                        addr_str = '0x{:x}'.format(self.addr + row * reg_byte_size)
                    if 0 <= row < len(self.values) and row in self.highlights:
                        return '{} ({})'.format(addr_str, ', '.join(self.highlights[row]))
                    else:
                        return addr_str
                elif col == 1:
                    return self.values[row].get('addr', 0)
                elif col == 2:
                    return self.values[row].get('cmt', '')
                elif col == 3:
                    addr = self.values[row].get('addr', 0)
                    func = ida_funcs.get_func(addr)
                    if func is None or func.start_ea > addr:
                        return QVariant()
                    name = ida_name.get_name(func.start_ea)
                    off = addr - func.start_ea
                    return '{} + 0x{:x}'.format(name, off)
            elif role == Qt.BackgroundRole:
                if 0 <= row < len(self.values) and row in self.highlights:
                    return QBrush(QColor(Qt.yellow))
            return QVariant()
        except Exception as ex:
            print ex
    
    def setData(self, index, value, role):
        row = index.row()
        col = index.column()
        if role in (Qt.EditRole, Qt.DisplayRole):
            if row == len(self.values):
                self.insertRows(len(self.values), 1, QModelIndex())
            if col == 1:
                self.values[row]['addr'] = parse_int(value)
            elif col == 2:
                self.values[row]['cmt'] = value

        return True

    def flags(self, index):
        row = index.row()
        col = index.column()

        flags = Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsDragEnabled
        if col in (1, 2):
            flags |= Qt.ItemIsEditable
        if row == -1 and col == -1:
            flags |= Qt.ItemIsDropEnabled
        return flags

    def insertRows(self, row, count, parent):
        self.beginInsertRows(parent, row, row + count - 1)
        self.values = self.values[:row] + [{} for _ in range(count)] + self.values[row:]
        self.endInsertRows()
        return True

    def removeRows(self, row, count, parent):
        if row < len(self.values) and row + count <= len(self.values):
            self.beginRemoveRows(parent, row, row + count - 1)
            self.values = self.values[:row] + self.values[row + count:]
            self.endRemoveRows()
            return True
        return False

    def dropMimeData(self, data, action, row, col, parent):
        if row == -1 or row > len(self.values):
            return False
        return super(RopModel, self).dropMimeData(data, action, row, 0, parent)

    def supportedDropActions(self):
        return Qt.MoveAction | Qt.CopyAction


class HexDelegate(QStyledItemDelegate):

    def displayText(self, value, locale):
        try:
            return '0x%x' % value
        except TypeError:
            return value

    def setEditorData(self, editor, index):
        editor.setText(self.displayText(index.data(), None))


class RopView(QTableView):

    def __init__(self, parent):
        super(RopView, self).__init__(parent)
        self.verticalHeader().hide()
        self.verticalHeader().setDefaultSectionSize(20)
        #self.horizontalHeader().hide()
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setDropIndicatorShown(True)
        self.setDragDropMode(self.DragDrop);
        self.setDragDropOverwriteMode(False);
        self.setDefaultDropAction(Qt.MoveAction)
        self.setItemDelegateForColumn(1, HexDelegate())
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.contextMenu)

        # actions
        self.del_act = QAction('Delete', self)
        self.del_act.triggered.connect(self.deleteSelectedRows)
        self.del_act.setShortcut('Delete')
        self.addAction(self.del_act)

        self.jump_act = QAction('Jump to', self)
        self.jump_act.triggered.connect(self.jumpTo)
        self.jump_act.setShortcut('G')
        self.addAction(self.jump_act)

    def contextMenu(self, point):

        select = self.selectionModel()

        menu = QMenu(self)
        menu.addAction(self.del_act)
        menu.addAction(self.jump_act)
        menu.popup(self.viewport().mapToGlobal(point))

    def deleteSelectedRows(self, checked):
        select = self.selectionModel()
        if select.hasSelection():
            selection = select.selectedRows()
            rows = sorted([i.row() for i in selection], reverse=True)
            for idx in rows:
                self.model().removeRow(idx)

    def jumpTo(self):
        select = self.selectionModel()
        if select.hasSelection():
            values = self.model().values
            selection = select.selectedRows()
            idx = [i.row() for i in selection][0]
            if 0 <= idx < len(values):
                addr = values[idx].get('addr', -1)
                IDAAPI_Jump(addr)


class RopTracer:

    def __init__(self, owner):
        self.owner = owner
        self.contexts = []

    def clear(self):
        self.contexts = []

    def trace(self):

        if len(self.contexts) > 0 and self.contexts[-1]['pc'] == self.owner.pc:
            return

        line = UEMU_HELPERS.trim_spaces(IDAAPI_GetDisasm(self.owner.pc, 0))
        context = {'pc': self.owner.pc, 'line': line, 'regs': {}}

        arch = UEMU_HELPERS.get_arch()
        regs_map = UEMU_HELPERS.get_register_map(arch)
        for name, ue_reg_id in regs_map:
            context['regs'][name] = self.owner.mu.reg_read(ue_reg_id)

        self.contexts.append(context)

    def get_trace(self):

        arch = UEMU_HELPERS.get_arch()
        reg_map = {i[1]: i[0] for i in UEMU_HELPERS.get_register_map(arch)}

        _, uc_reg_sp = UEMU_HELPERS.get_stack_register(arch)
        uc_reg_pc = self.owner.uc_reg_pc
        

        reg_sp_mnem = reg_map[uc_reg_sp]
        reg_pc_mnem = reg_map[uc_reg_pc]

        n = len(self.contexts)

        lines = []
        for i in range(n):
            context = self.contexts[i]
            next_context = self.contexts[i + 1] if i + 1 < n else None

            line_disas = context['line']
            regs = context['regs']

            reg_changes = []
            if next_context is not None:
                reg_names = regs.keys()
                next_regs = next_context['regs']
                for reg_name in reg_names:
                    if reg_name in (reg_sp_mnem, reg_pc_mnem):
                        continue
                    if next_regs[reg_name] != regs[reg_name]:
                        reg_changes.append('%s = %016X' % (reg_name, next_regs[reg_name]))
            line_addr = '%016X' % context['pc']
            line_changes = ', '.join(reg_changes)

            lines.append((line_addr, line_disas, line_changes))

        return lines


class RopTab(QWidget):

    def __init__(self, parent, model):
        super(RopTab, self).__init__(parent)
        self.model = model
        self.init_ui()

    def init_ui(self):
        self.rop_view = RopView(self)
        self.rop_view.setModel(self.model)

        self.name_edit = QLineEdit(self.model.name, self)
        if type(self.model.addr) in (unicode, str):
            self.addr_edit = QLineEdit(self.model.addr, self)
        else:
            self.addr_edit = QLineEdit('0x{:x}'.format(self.model.addr), self)
        self.size_edit = QLineEdit('0x{:x}'.format(self.model.size), self)
        self.psize_edit = QLineEdit('0x{:x}'.format(self.model.prev_size), self)

        self.name_edit.editingFinished.connect(self.name_edited)
        self.addr_edit.editingFinished.connect(self.addr_edited)
        self.size_edit.editingFinished.connect(self.size_edited)
        self.psize_edit.editingFinished.connect(self.psize_edited)

        edit_layout = QHBoxLayout()
        edit_layout.addWidget(QLabel('Name:'))
        edit_layout.addWidget(self.name_edit)
        edit_layout.addWidget(QLabel('Address:'))
        edit_layout.addWidget(self.addr_edit)
        edit_layout.addWidget(QLabel('Size:'))
        edit_layout.addWidget(self.size_edit)
        edit_layout.addWidget(QLabel('Prev. Size:'))
        edit_layout.addWidget(self.psize_edit)

        layout = QVBoxLayout()
        layout.addLayout(edit_layout)
        layout.addWidget(self.rop_view)
        self.setLayout(layout)

    def name_edited(self):
        self.model.name = self.name_edit.text()
        self.model.nameChanged.emit()

    def addr_edited(self):
        self.model.addr = parse_int(self.addr_edit.text(), None)
        if self.model.addr is None:
            self.model.addr = self.addr_edit.text()
        if type(self.model.addr) in (str, unicode):
            self.addr_edit.setText(self.model.addr)
        else:
            self.addr_edit.setText('0x{:x}'.format(self.model.addr))
        self.model.dataChanged.emit(QModelIndex(), QModelIndex())

    def size_edited(self):
        self.model.size = parse_int(self.size_edit.text())
        self.size_edit.setText('0x{:x}'.format(self.model.size))
        self.model.dataChanged.emit(QModelIndex(), QModelIndex())

    def psize_edited(self):
        self.model.prev_size = parse_int(self.psize_edit.text())
        self.psize_edit.setText('0x{:x}'.format(self.model.prev_size))
        self.model.dataChanged.emit(QModelIndex(), QModelIndex())

class RopEditorView(PluginForm):

    DEFAULT_SP = 0xffff1000
    DEFAULT_PC = 0xdeadbeef
    DEFAULT_STACK_SIZE = 0xf000
    DEFAULT_STACK_PREV_SIZE = 0x1000

    def __init__(self, owner):
        self.owner = owner
        super(RopEditorView, self).__init__()
        arch = UEMU_HELPERS.get_arch()
        self.sp_mnem, self.uc_reg_sp = UEMU_HELPERS.get_stack_register(arch)
        self.uc_reg_pc = self.owner.unicornEngine.uc_reg_pc
        reg_map = UEMU_HELPERS.get_register_map(arch)
        self.pc_mnem = {i[1]: i[0] for i in reg_map}[self.uc_reg_pc]
        self.rop_models = [
            RopModel('Stack', self.sp_mnem,
                     self.DEFAULT_STACK_SIZE,
                     self.DEFAULT_STACK_PREV_SIZE,
            )
        ]

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.init_ui()

    def get_default_ctx_src(self):
        src = ''
        src += '{} = 0x{:x} # stack pointer\n'.format(self.sp_mnem, self.DEFAULT_SP)
        src += '{} = 0x{:x} # program counter\n'.format(self.pc_mnem, self.DEFAULT_PC)
        return src

    def init_ui(self):
        self.text_edit = QTextEdit(self.parent)
        src = self.get_default_ctx_src()
        self.text_edit.setPlainText(src)

        self.init_btn = QPushButton("Initiate", self.parent)
        self.rop_save_btn = QPushButton("Save", self.parent)
        self.rop_load_btn = QPushButton("Load", self.parent)
        self.dump_trace_btn = QPushButton("Dump trace", self.parent)
        self.dump_rop_btn = QPushButton("Dump rop", self.parent)

        self.init_btn.clicked.connect(self.OnInitialize)
        self.rop_save_btn.clicked.connect(self.OnRopSave)
        self.rop_load_btn.clicked.connect(self.OnRopLoad)
        self.dump_trace_btn.clicked.connect(self.OnDumpTrace)
        self.dump_rop_btn.clicked.connect(self.OnDumpRop)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.init_btn)
        button_layout.addWidget(self.rop_save_btn)
        button_layout.addWidget(self.rop_load_btn)
        button_layout.addWidget(self.dump_trace_btn)
        button_layout.addWidget(self.dump_rop_btn)

        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.addTab(self.text_edit, 'Context')
        self.tabs.tabBar().tabButton(0, QTabBar.RightSide).deleteLater()
        self.tabs.tabBar().setTabButton(0, QTabBar.RightSide, None)
        self.tabs.tabCloseRequested.connect(self.handle_tab_close)


        tb = QToolButton()
        tb.setText('+')
        tb.clicked.connect(self.OnNewTab)
        self.tabs.addTab(QWidget(), '')
        self.tabs.setTabEnabled(1, False)
        self.tabs.tabBar().setTabButton(1, QTabBar.RightSide, tb)

        self.update_rop_views()

        layout = QVBoxLayout()
        layout.addWidget(self.tabs)
        layout.addLayout(button_layout)

        self.parent.setLayout(layout)

    def update_rop_views(self):
        n = max(0, self.tabs.count() - 2)
        for i in range(n):
            self.tabs.removeTab(1)
        for i, rop_model in enumerate(self.rop_models):
            self.tabs.insertTab(i + 1, RopTab(self.parent, rop_model), rop_model.name)

            class TabNameSetter:

                def __init__(self, parent, i):
                    self.parent = parent
                    self.i = i

                def __call__(self):
                    self.parent.tabs.setTabText(self.i + 1, self.parent.rop_models[self.i].name)

            rop_model.nameChanged.connect(TabNameSetter(self, i))

    def handle_tab_close(self, index):
        # tab index to rop_model index
        index = index - 1
        del self.rop_models[index]
        self.update_rop_views()

    def update_context(self):
        mu = self.owner.unicornEngine.mu
        arch = UEMU_HELPERS.get_arch()
        reg_map = dict(UEMU_HELPERS.get_register_map(arch))
        reg_bit_size = UEMU_HELPERS.get_register_bits(arch)
        reg_byte_size = reg_bit_size // 8
        for rop_model in self.rop_models:
            rop_model.highlights = {}
        for reg in reg_map:
            value = self.owner.unicornEngine.mu.reg_read(reg_map[reg])
            for rop_model in self.rop_models:
                if rop_model.init_addr is not None and\
                        rop_model.init_addr <= value <= rop_model.init_addr + rop_model.size:
                    index = (value - rop_model.init_addr) // reg_byte_size
                    if index in rop_model.highlights:
                        rop_model.highlights[index].append(reg)
                    else:
                        rop_model.highlights[index] = [reg]
        for rop_model in self.rop_models:
            rop_model.dataChanged.emit(QModelIndex(), QModelIndex())

    def OnNewTab(self):
        self.rop_models.append(
            RopModel('Tab', self.sp_mnem,
                 self.DEFAULT_STACK_SIZE,
                 self.DEFAULT_STACK_PREV_SIZE,
            )
        )
        self.update_rop_views()

    def OnInitialize(self):

        self.follow_regs = {}

        ue = self.owner.unicornEngine
        if ue.is_active():
            ue.reset()

        self.owner.emu_hooks = {}

        # evaluate context
        ctx = {
            self.sp_mnem: self.DEFAULT_SP,
            self.pc_mnem: self.DEFAULT_PC,
            'hook': self.owner.set_emu_hook,
        }
        src = self.text_edit.toPlainText()
        try:
            exec(
                src,
                {k: v for k, v in globals().items() if k.startswith('UC_')},
                ctx
            )
        except Exception as ex:
            crauemu_log('[!] context evaluation error: {}'.format(ex))

        arch = UEMU_HELPERS.get_arch()
        reg_map = dict(UEMU_HELPERS.get_register_map(arch))
        reg_bit_size = UEMU_HELPERS.get_register_bits(arch)

        pc = ctx[self.pc_mnem]

        self.owner.rop_tracer = RopTracer(ue)
        self.owner.init_from_crauemu = True
        ue.run_from(pc)
        self.owner.init_from_crauemu = False

        sp = ctx[self.sp_mnem]

        for mnem, reg_value in ctx.items():
            if mnem in reg_map:
                ue.mu.reg_write(reg_map[mnem], reg_value)

        for rop_model in self.rop_models:
            addr = rop_model.addr
            values = rop_model.values
            if type(addr) in (str, unicode):
                addr = ctx.get(addr, None)
            if addr is None:
                crauemu_log('[!] Error address at {} rop tab: {}'.format(rop_model.name, rop_model.addr))
                continue
            rop_model.init_addr = addr
            start = addr - rop_model.prev_size
            end = addr + rop_model.size

            ue.map_memory(start, end - start)
            ue.mu.mem_write(addr, struct.pack(
                ('%dQ' if reg_bit_size == 64 else '%dI')  % len(values),
                *[i.get('addr', 0) for i in values]))

        self.owner.update_context(ue.pc, ue.mu)

    def OnRopSave(self):
        file_path = IDAAPI_AskFile(1, "*.rop", "Rop Save")
        if file_path is not None:
            dump = {'ctx': self.text_edit.toPlainText(), 'rops': []}
            for rop_model in self.rop_models:
                dump['rops'].append({
                    'name': rop_model.name,
                    'addr': rop_model.addr,
                    'size': rop_model.size,
                    'psize': rop_model.prev_size,
                    'values': rop_model.values
                })
            with open(file_path, 'wb') as f:
                json.dump(dump, f)

    def OnRopLoad(self):
        file_path = IDAAPI_AskFile(0, "*.rop", "Rop Load")
        if file_path is not None:
            with open(file_path, 'rb') as f:
                dump = json.load(f)
            self.text_edit.setPlainText(dump['ctx'])
            # load old save
            if 'rop' in dump:
                values = dump['rop']
                self.rop_models = [
                    RopModel('Stack', self.sp_mnem,
                             self.DEFAULT_STACK_SIZE,
                             self.DEFAULT_STACK_PREV_SIZE,
                             values)
                ]
            else:
                self.rop_models = []
                for rop in dump['rops']:
                    name = rop['name']
                    addr = rop['addr']
                    size = rop['size']
                    psize = rop['psize']
                    values = rop['values']
                    self.rop_models.append(RopModel(name, addr, size, psize, values))
            self.update_rop_views()


    def OnDumpTrace(self):
        if self.owner.unicornEngine.rop_tracer is None:
            crauemu_log('[!] Rop tracer not found')
            return
        file_path = IDAAPI_AskFile(1, "*.log", "Trac(e dump")
        if file_path is not None:
            with open(file_path, 'w') as f:
                for line_addr, line_disas, line_changes in self.owner.unicornEngine.rop_tracer.get_trace():
                    if len(line_changes) > 0:
                        f.write('%s: %s  %s\n' % (line_addr, line_disas, '# ' + line_changes))
                    else:
                        f.write('%s: %s\n' % (line_addr, line_disas))
                
    def OnDumpRop(self):
        file_path = IDAAPI_AskFile(1, "*.py", "Rop dump")
        if file_path is not None:
            with open(file_path, 'w') as f:
                f.write('import struct\n\n\n')
                f.write('REBASE =  0x0\n')
                f.write('rop = b\'\'\n')
                arch = UEMU_HELPERS.get_arch()
                reg_bit_size = UEMU_HELPERS.get_register_bits(arch)
                fmt = 'I' if reg_bit_size == 32 else 'Q'
                for rop_model in self.rop_models:
                    name = rop_model.name
                    values = rop_model.values
                    for i in values:
                        addr = i['addr']
                        if IDAAPI_IsLoaded(addr):
                            f.write('rop_%s += struct.pack(\'%s\', REBASE + 0x%x)\n' % (name, fmt, addr))
                        else:
                            f.write('rop_%s += struct.pack(\'%s\', 0x%x)\n' % (name, fmt, addr))

    def OnClose(self, form):
        self.owner.rop_editor_view_closed()

class crauEmuPlugin(uEmuPlugin):

    def __init__(self):
        hooks = uEmuExtensionHooks()
        hooks.init_context = self.hook_init_context
        hooks.trace_log = self.hook_trace_log
        hooks.emu_step = self.hook_emu_step
        self.ropEditorView = None
        self.ropTraceView = None
        self.rop_tracer = None
        self.init_from_crauemu = False
        self.emu_hooks = {}

        self.settings['trace_inst'] = True
        self.settings['follow_pc'] = True
        self.settings['lazy_mapping'] = True

        super(crauEmuPlugin, self).__init__("crauEmu", hooks)

    def add_custom_menu(self):
        self.MENU_ITEMS.append(UEMU_HELPERS.MenuItem(self.plugin_name + ":rop_trace_view",    self.show_rop_trace_view,   "Show Rop Trace View",        "Show Rop Trace View",       "SHIFT+CTRL+ALT+T",     True    ))
        self.MENU_ITEMS.append(UEMU_HELPERS.MenuItem(self.plugin_name + ":rop_editor_view",   self.show_rop_editor_view,  "Show Rop Editor View",       "Show Rop Editor View",      "SHIFT+CTRL+ALT+R",     True    ))
        self.MENU_ITEMS.append(UEMU_HELPERS.MenuItem("-",                                     self.do_nothing,            "",                           None,                        None,                   True    ))

    ### uEmu hooks

    def hook_init_context(self):
        return self.init_from_crauemu

    def hook_trace_log(self, pc):
        if self.rop_tracer is not None:
            self.rop_tracer.trace()
        return True

    def hook_emu_step(self, pc):
        if pc in self.emu_hooks:
            self.emu_hooks[pc](self.unicornEngine.mu)
            return True
        return False

    def rop_editor_view_closed(self):
        self.ropEditorView = None

    def rop_trace_view_closed(self):
        self.ropTraceView = None

    def show_rop_trace_view(self):
        if not self.unicornEngine.is_active():
            crauemu_log("Emulator is not active")
            return

        if self.ropTraceView is None:
            self.ropTraceView = uEmuRopTraceView(self)
            self.ropTraceView.Create("uEmu Rop Trace View")
            self.ropTraceView.SetContent(self.rop_tracer)
            self.ropTraceView.Show()
            self.ropTraceView.Refresh()

    def show_rop_editor_view(self):
        if self.ropEditorView is None:
            self.ropEditorView = RopEditorView(self)
            self.ropEditorView.Show('RopEditor')

    def update_context(self, address, context):
        super(crauEmuPlugin, self).update_context(address, context)

        if self.ropEditorView is not None:
            self.ropEditorView.update_context()
        if self.ropTraceView is not None:
            self.ropTraceView.SetContent(self.rop_tracer)

    def close_windows(self):
        super(crauEmuPlugin, self).close_windows()

        if self.ropEditorView is not None:
            self.ropEditorView.Close(0)
            self.ropEditorView = None

        if self.ropTraceView is not None:
            self.ropTraceView.Close()
            self.ropTraceView = None

    def set_emu_hook(self, addr, func):
        self.emu_hooks[addr] = func


def PLUGIN_ENTRY():
    return crauEmuPlugin()

if CRAUEMU_USE_AS_SCRIPT:
    if __name__ == '__main__':
        crauEmu = crauEmuPlugin()
        crauEmu.init()
        crauEmu.run()

