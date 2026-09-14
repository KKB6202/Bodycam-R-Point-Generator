from __future__ import annotations

import ctypes
import hashlib
import json
import queue
import threading
import time
import tkinter as tk
import customtkinter as ctk
import frida
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk
from PIL import Image, ImageDraw, ImageTk

PROCESS_NAME = "Bodycam-Win64-Shipping.exe"

EXPECTED_SHA256 = (
    "F6C5ED24CA26D3BF2AA3101E069AA77D8E08B233D6CD3F0D205EE6A09754E83B"
)

DEFAULT_AMOUNT = 500
MAX_QA_AMOUNT = 10_000

CONFIG = {
    "kind": "rpoints",
    "amount": DEFAULT_AMOUNT,
    "get": "BodycamCheatManager.GetBalance",
    "set": "BodycamCheatManager.SetBalance",
    "fetched": "BodycamCheatManager.OnBalanceFetchedCallback",
    "updated": "BodycamCheatManager.OnBalanceUpdateCallback",
    "fetchFoundOffset": 4,
    "updateSuccessOffset": 13,
}

#If this breaks Pray
JAVASCRIPT = r"""
'use strict';

const CFG = __CONFIG__;

const game = Process.getModuleByName('Bodycam-Win64-Shipping.exe');

// Bodycam build SHA-256 F6C5ED24
const O = {
    gObjects: 0x9AA7270,
    fNameBlocks: 0x99C3AD0
};


function rp(a) {
    try {
        return a.readPointer();
    } catch (_) {
        return ptr(0);
    }
}


function u32(a) {
    try {
        return a.readU32();
    } catch (_) {
        return null;
    }
}


function fname(index) {
    try {
        const block = game.base
            .add(O.fNameBlocks)
            .add((index >>> 16) * 8)
            .readPointer();

        const entry = block.add((index & 0xffff) * 2);

        const h = entry.readU16();
        const len = h >>> 6;

        if (len < 1 || len > 512)
            return null;

        return (h & 1)
            ? entry.add(2).readUtf16String(len)
            : entry.add(2).readUtf8String(len);

    } catch (_) {
        return null;
    }
}


function name(o) {
    const n = o.isNull()
        ? null
        : u32(o.add(0x18));

    return n === null
        ? null
        : fname(n);
}


try {

    const array = game.base.add(O.gObjects);

    const chunks = rp(array);
    const count = u32(array.add(0x14));
    const chunkCount = u32(array.add(0x1c));

    let controller = ptr(0);
    let cheatClass = ptr(0);
    let gameplayStatics = ptr(0);

    const fn = {};

    const wanted = new Set([
        'GameplayStatics.SpawnObject',
        CFG.get,
        CFG.set,
        CFG.fetched,
        CFG.updated,
    ]);


    for (let i = 0; i < count; i++) {

        const ci = i >>> 16;

        if (ci >= chunkCount)
            continue;

        const chunk = rp(chunks.add(ci * 8));

        if (chunk.isNull())
            continue;

        const o = rp(
            chunk.add(
                (i & 0xffff) * 0x18
            )
        );

        if (o.isNull())
            continue;

        const c = rp(o.add(0x10));

        const cn = name(c);
        const on = name(o);


        if (cn === 'PC_Bodycam_C') {

            const player = rp(o.add(0x348));

            if (
                name(rp(player.add(0x10))) ===
                'LocalPlayer'
            ) {
                controller = o;
                cheatClass = rp(o.add(0x418));
            }

        } else if (
            on === 'Default__GameplayStatics' &&
            cn === 'GameplayStatics'
        ) {

            gameplayStatics = o;

        } else if (cn === 'Function') {

            const qualified =
                name(rp(o.add(0x20))) +
                '.' +
                on;

            if (wanted.has(qualified))
                fn[qualified] = o;
        }
    }


    if (
        controller.isNull() ||
        cheatClass.isNull() ||
        gameplayStatics.isNull()
    ) {
        throw new Error(
            'required runtime object missing'
        );
    }


    for (const key of wanted) {
        if (!(key in fn))
            throw new Error(
                'missing UFunction ' + key
            );
    }


    const peAddress =
        gameplayStatics
            .readPointer()
            .add(0x278)
            .readPointer();


    const processEvent =
        new NativeFunction(
            peAddress,
            'void',
            [
                'pointer',
                'pointer',
                'pointer'
            ]
        );


    const result = {
        event:
            'qa_' +
            CFG.kind +
            '_fixed_result',

        requestedAmount:
            CFG.amount,

        requestedOperationType:
            0,

        baseline:
            null,

        update:
            null,

        finalRead:
            null,
    };


    let phase = 'baseline';


    Interceptor.attach(
        peAddress,
        {
            onEnter(args) {

                const f = args[1];
                const p = args[2];

                if (p.isNull())
                    return;


                if (
                    f.equals(
                        fn[CFG.fetched]
                    )
                ) {

                    const v = {
                        value:
                            p.readS32(),

                        found:
                            p
                                .add(
                                    CFG.fetchFoundOffset
                                )
                                .readU8()
                    };


                    if (
                        phase ===
                        'baseline'
                    ) {
                        result.baseline = v;
                    } else {
                        result.finalRead = v;
                    }


                } else if (
                    f.equals(
                        fn[CFG.updated]
                    )
                ) {

                    result.update = {

                        amount:
                            p.readS32(),

                        oldValue:
                            p
                                .add(4)
                                .readS32(),

                        newValue:
                            p
                                .add(8)
                                .readS32(),

                        operationType:
                            p
                                .add(12)
                                .readU8(),

                        success:
                            p
                                .add(
                                    CFG.updateSuccessOffset
                                )
                                .readU8(),
                    };
                }
            },
        }
    );


    const spawn =
        Memory.alloc(24);

    spawn.writeByteArray(
        new Array(24).fill(0)
    );

    spawn.writePointer(
        cheatClass
    );

    spawn
        .add(8)
        .writePointer(
            controller
        );


    processEvent(
        gameplayStatics,
        fn[
            'GameplayStatics.SpawnObject'
        ],
        spawn
    );


    const manager =
        spawn
            .add(16)
            .readPointer();


    if (manager.isNull()) {
        throw new Error(
            'SpawnObject returned null'
        );
    }


    result.controller =
        controller.toString();

    result.manager =
        manager.toString();


    // Get starting balance
    processEvent(
        manager,
        fn[CFG.get],
        ptr(0)
    );


    setTimeout(() => {

        phase = 'update';

        const p =
            Memory.alloc(5);

        p.writeS32(
            CFG.amount
        );

        p
            .add(4)
            .writeU8(0);


        // Update balance
        processEvent(
            manager,
            fn[CFG.set],
            p
        );


        setTimeout(() => {

            phase = 'final';


            // Get updated balance
            processEvent(
                manager,
                fn[CFG.get],
                ptr(0)
            );


            setTimeout(() => {

                result.completedAt =
                    new Date().toISOString();

                send(result);

            }, 3500);

        }, 5500);

    }, 3500);


} catch (error) {

    send({
        event:
            'qa_' +
            CFG.kind +
            '_fixed_error',

        error:
            String(error),

        stack:
            error.stack || null
    });
}
"""
#JS ends here

def process_path(pid: int) -> Path:

    kernel32 = ctypes.WinDLL(
        "kernel32",
        use_last_error=True
    )

    handle = kernel32.OpenProcess(
        0x1000,
        False,
        pid
    )

    if not handle:
        raise OSError(
            ctypes.get_last_error(),
            "OpenProcess failed"
        )

    try:

        size = ctypes.c_ulong(
            32768
        )

        buffer = ctypes.create_unicode_buffer(
            size.value
        )

        if not kernel32.QueryFullProcessImageNameW(
            handle,
            0,
            buffer,
            ctypes.byref(size)
        ):
            raise OSError(
                ctypes.get_last_error(),
                "QueryFullProcessImageNameW failed"
            )

        return Path(
            buffer.value
        )

    finally:
        kernel32.CloseHandle(
            handle
        )


def sha256(path: Path) -> str:

    digest = hashlib.sha256()

    with path.open("rb") as stream:

        for block in iter(
            lambda:
            stream.read(
                1024 * 1024
            ),
            b""
        ):
            digest.update(block)

    return digest.hexdigest().upper()


def check_game_version() -> tuple[str, str]:
    """Return the running game's version state without attaching to it."""

    try:
        device = frida.get_local_device()
        matches = [
            process
            for process in device.enumerate_processes()
            if process.name == PROCESS_NAME
        ]

        if not matches:
            return "not_running", "Bodycam is not running"

        if len(matches) != 1:
            return "error", f"Found {len(matches)} Bodycam processes"

        exe = process_path(matches[0].pid)
        actual_hash = sha256(exe)

        if actual_hash == EXPECTED_SHA256:
            return "correct", "Compatible game version detected"

        return "incorrect", "Incompatible game version detected"

    except Exception as exc:
        return "error", f"Version check failed: {exc}"

def apply_points(
    amount: int,
    status_callback=None
) -> dict:

    def status(text):

        if status_callback:
            status_callback(text)


    if not 1 <= amount <= MAX_QA_AMOUNT:
        raise ValueError(
            f"Amount must be between 1 and {MAX_QA_AMOUNT:,}."
        )


    status(
        "Looking for Bodycam..."
    )


    device = frida.get_local_device()


    matches = [
        p
        for p in device.enumerate_processes()
        if p.name == PROCESS_NAME
    ]


    if len(matches) == 0:
        raise RuntimeError(
            "Bodycam is not running.\n\n"
            "Start Bodycam first and then try again."
        )


    if len(matches) != 1:
        raise RuntimeError(
            f"Expected one Bodycam process, "
            f"but found {len(matches)}."
        )


    process = matches[0]


    status(
        f"Found Bodycam. PID: {process.pid}"
    )

    status(
        "Checking game version..."
    )


    exe = process_path(
        process.pid
    )


    actual_hash = sha256(
        exe
    )


    if actual_hash != EXPECTED_SHA256:

        raise RuntimeError(
            "This version of Bodycam does not match "
            "the version expected by this program.\n\n"
            f"Current SHA-256:\n{actual_hash}\n\n"
            f"Expected SHA-256:\n{EXPECTED_SHA256}"
        )


    status(
        "Game version verified."
    )

    config = dict(CONFIG)

    config["amount"] = amount


    source = JAVASCRIPT.replace(
        "__CONFIG__",
        json.dumps(
            config,
            separators=(",", ":")
        )
    )


    result = None


    def on_message(message, data):

        nonlocal result

        if message.get("type") == "error":

            result = {
                "event": "python_frida_error",
                "error": message.get(
                    "description",
                    str(message)
                ),
                "stack": message.get(
                    "stack"
                ),
            }

            return


        result = message.get(
            "payload",
            message
        )

    status(
        "Attaching to Bodycam..."
    )


    session = device.attach(
        process.pid
    )


    script = session.create_script(
        source
    )


    script.on(
        "message",
        on_message
    )


    script.load()


    status(
        f"Applying {amount:,} points..."
    )


    try:

        deadline = (
            time.monotonic()
            + 25
        )


        while (
            result is None
            and
            time.monotonic() < deadline
        ):

            time.sleep(
                0.05
            )


    finally:

        try:
            script.unload()
        except Exception:
            pass

        try:
            session.detach()
        except Exception:
            pass


    if result is None:

        raise RuntimeError(
            "Operation timed out.\n"
            "Check your current point total before "
            "trying again..."
        )


    result["executable"] = str(
        exe
    )

    result["sha256"] = actual_hash


    if not result.get(
        "event",
        ""
    ).endswith("_result"):

        error = result.get(
            "error",
            "Unknown Frida error"
        )

        raise RuntimeError(
            error
        )


    return result

class LegacyPointsGUI:

    def __init__(self, root):

        self.root = root
    

        self.root.title(
            "Bodycam R-Points Generator"
        )

        self.root.geometry(
            "620x520"
        )

        self.root.minsize(
            550,
            450
        )


        self.message_queue = queue.Queue()

        main = ttk.Frame(
            root,
            padding=20
        )

        main.pack(
            fill="both",
            expand=True
        )

        title = ttk.Label(
            main,
            text="Bodycam RPoints",
            font=(
                "Segoe UI",
                20,
                "bold"
            )
        )

        title.pack(
            pady=(
                0,
                5
            )
        )


        subtitle = ttk.Label(
            main,
            text=(
                "Enter the amount of points you want \n"
                "You can only add 10,000 at a time with max being 40,000 \n"
            )
        )

        subtitle.pack(
            pady=(
                0,
                20
            )
        )

        amount_frame = ttk.Frame(
            main
        )

        amount_frame.pack(
            fill="x",
            pady=10
        )


        ttk.Label(
            amount_frame,
            text="Points:"
        ).pack(
            side="left"
        )


        self.amount_var = tk.StringVar(
            value=str(
                DEFAULT_AMOUNT
            )
        )


        self.amount_entry = ttk.Entry(
            amount_frame,
            textvariable=self.amount_var,
            font=(
                "Segoe UI",
                14
            )
        )

        self.amount_entry.pack(
            side="left",
            fill="x",
            expand=True,
            padx=(
                10,
                0
            )
        )

        self.apply_button = ttk.Button(
            main,
            text="Apply Points",
            command=self.start_apply
        )

        self.apply_button.pack(
            fill="x",
            pady=(
                10,
                15
            ),
            ipady=8
        )

        self.progress = ttk.Progressbar(
            main,
            mode="indeterminate"
        )

        self.progress.pack(
            fill="x",
            pady=(
                0,
                10
            )
        )

        self.status_var = tk.StringVar(
            value="Ready"
        )


        self.status_label = ttk.Label(
            main,
            textvariable=self.status_var
        )

        self.status_label.pack(
            anchor="w",
            pady=(
                0,
                10
            )
        )

        self.output = scrolledtext.ScrolledText(
            main,
            height=25,
            font=(
                "Consolas",
                9
            ),
            state="disabled"
        )

        self.output.pack(
            fill="both",
            expand=True
        )


        self.root.bind(
            "<Return>",
            lambda event:
            self.start_apply()
        )


        self.amount_entry.focus_set()


        self.root.after(
            100,
            self.process_messages
        )


    def log(self, text):

        self.output.config(
            state="normal"
        )

        self.output.insert(
            "end",
            text + "\n"
        )

        self.output.see(
            "end"
        )

        self.output.config(
            state="disabled"
        )


    def clear_output(self):

        self.output.config(
            state="normal"
        )

        self.output.delete(
            "1.0",
            "end"
        )

        self.output.config(
            state="disabled"
        )

    def start_apply(self):

        try:

            amount = int(
                self.amount_var.get()
                .replace(",", "")
                .strip()
            )

        except ValueError:

            messagebox.showerror(
                "Invalid Amount",
                "Enter a whole number."
            )

            return


        if not 1 <= amount <= MAX_QA_AMOUNT:

            messagebox.showerror(
                "Invalid Amount",
                (
                    "Points must be between "
                    f"1 and {MAX_QA_AMOUNT:,}."
                )
            )

            return


        self.clear_output()


        self.log(
            f"Requested points: {amount:,}"
        )


        self.apply_button.config(
            state="disabled"
        )


        self.amount_entry.config(
            state="disabled"
        )


        self.progress.start(
            10
        )


        self.status_var.set(
            "Starting..."
        )


        worker = threading.Thread(
            target=self.worker,
            args=(amount,),
            daemon=True
        )


        worker.start()

    def worker(
        self,
        amount
    ):

        try:

            result = apply_points(
                amount,
                status_callback=lambda msg:
                    self.message_queue.put(
                        (
                            "status",
                            msg
                        )
                    )
            )


            self.message_queue.put(
                (
                    "success",
                    result
                )
            )


        except Exception as exc:

            self.message_queue.put(
                (
                    "error",
                    str(exc)
                )
            )

    def process_messages(self):

        try:

            while True:

                msg_type, data = (
                    self.message_queue
                    .get_nowait()
                )


                if msg_type == "status":

                    self.status_var.set(
                        data
                    )

                    self.log(
                        data
                    )


                elif msg_type == "success":

                    self.finish()

                    self.status_var.set(
                        "Completed successfully"
                    )


                    self.log(
                        "\nSUCCESS"
                    )


                    self.log(
                        json.dumps(
                            data,
                            ensure_ascii=False,
                            indent=2
                        )
                    )


                    requested = data.get(
                        "requestedAmount"
                    )


                    final_read = data.get(
                        "finalRead"
                    )


                    if isinstance(
                        final_read,
                        dict
                    ):

                        final_value = (
                            final_read.get(
                                "value"
                            )
                        )

                    else:

                        final_value = None


                    message = (
                        "Operation completed successfully."
                    )


                    if requested is not None:

                        message += (
                            f"\n\nRequested amount: "
                            f"{requested:,}"
                        )


                    if final_value is not None:

                        message += (
                            f"\nFinal balance: "
                            f"{final_value:,}"
                        )


                    messagebox.showinfo(
                        "Success",
                        message
                    )


                elif msg_type == "error":

                    self.finish()

                    self.status_var.set(
                        "Error"
                    )


                    self.log(
                        "\nERROR"
                    )


                    self.log(
                        data
                    )


                    messagebox.showerror(
                        "Error",
                        data
                    )


        except queue.Empty:
            pass


        self.root.after(
            100,
            self.process_messages
        )

    def finish(self):

        self.progress.stop()


        self.apply_button.config(
            state="normal"
        )


        self.amount_entry.config(
            state="normal"
        )

class PointsGUI(LegacyPointsGUI):

    BASE = (18, 3, 4)
    CARD = "#210A0B"
    CARD_BORDER = "#6F1A1C"
    INPUT = "#E8DDDD"
    INPUT_TEXT = "#2A0B0C"
    WHITE = "#F4F7FB"
    MUTED = "#C1A4A5"
    BLUE = "#AB2528"
    BLUE_HOVER = "#C9363A"
    BLUE_DIM = "#4A1214"
    SUCCESS = "#6FE6A8"
    ERROR = "#FF8D98"

    def __init__(self, root):
        self.root = root
        self.root.title("Bodycam R-Points Generator")
        self.root.geometry("750x700")
        self.root.resizable(False, False)
        self.root.configure(bg="#120304")

        ctk.set_appearance_mode("dark")
        self.message_queue = queue.Queue()
        self.console_visible = True
        self._gradient_job = None
        self._gradient_photo = None
        self._version_check_running = False

        self.background = tk.Canvas(
            root,
            bd=0,
            highlightthickness=0,
            bg="#120304"
        )
        self.background.pack(fill="both", expand=True)
        self.background_image = self.background.create_image(
            0, 0, anchor="nw"
        )

        # Draw the help button directly on the Canvas. A CustomTkinter button
        # cannot make its rounded corners truly transparent over a Tk canvas.
        self.help_circle = self.background.create_oval(
            18,
            18,
            58,
            58,
            fill=self.BLUE,
            outline="",
            tags=("help_button",)
        )
        self.help_text = self.background.create_text(
            38,
            38,
            text="?",
            fill=self.WHITE,
            font=("Segoe UI", 18, "bold"),
            tags=("help_button",)
        )
        self.background.tag_bind(
            "help_button", "<Button-1>", lambda _event: self.show_help()
        )
        self.background.tag_bind(
            "help_button", "<Enter>", self._help_enter
        )
        self.background.tag_bind(
            "help_button", "<Leave>", self._help_leave
        )

        self.content = ctk.CTkFrame(
            self.background,
            width=534,
            height=550,
            fg_color=self.CARD,
            corner_radius=0,
            border_width=0
        )
        self.content.pack_propagate(False)
        self.content_window = self.background.create_window(
            360, 350, window=self.content, anchor="center"
        )

        self.badge = ctk.CTkFrame(
            self.content,
            height=30,
            corner_radius=15,
            fg_color=self.BLUE_DIM
        )
        self.badge.pack(pady=(0, 12))

        self.version_dot = ctk.CTkLabel(
            self.badge,
            text="●",
            width=18,
            text_color=self.MUTED,
            font=ctk.CTkFont("Segoe UI", 13, "bold")
        )
        self.version_dot.pack(side="left", padx=(12, 0))

        self.badge_text = ctk.CTkLabel(
            self.badge,
            text="R-POINTS TOOL",
            text_color="#FFFFFF",
            font=ctk.CTkFont("Segoe UI", 11, "bold")
        )
        self.badge_text.pack(side="left", padx=(4, 12))

        self.title_label = ctk.CTkLabel(
            self.content,
            text="BODYCAM R-POINTS",
            text_color=self.WHITE,
            font=ctk.CTkFont("Segoe UI", 28, "bold")
        )
        self.title_label.pack()

        self.subtitle = ctk.CTkLabel(
            self.content,
            text=(
                "Enter the amount of points you want to add\n"
                "Maximum 10,000 points per operation \n"
                "If you go over 40,000 points in game it will cause issues"
            ),
            text_color=self.MUTED,
            justify="center",
            font=ctk.CTkFont("Segoe UI", 12)
        )
        self.subtitle.pack(pady=(5, 22))

        self.input_card = ctk.CTkFrame(
            self.content,
            corner_radius=20,
            fg_color="#321012",
            border_width=1,
            border_color=self.CARD_BORDER
        )
        self.input_card.pack(fill="x", pady=(0, 14))

        self.points_label = ctk.CTkLabel(
            self.input_card,
            text="POINTS TO ADD",
            text_color=self.MUTED,
            font=ctk.CTkFont("Segoe UI", 11, "bold")
        )
        self.points_label.pack(pady=(18, 7))

        self.amount_var = tk.StringVar(value=str(DEFAULT_AMOUNT))
        self.amount_entry = ctk.CTkEntry(
            self.input_card,
            textvariable=self.amount_var,
            height=48,
            corner_radius=14,
            fg_color=self.INPUT,
            border_width=0,
            text_color=self.INPUT_TEXT,
            justify="center",
            font=ctk.CTkFont("Segoe UI", 19, "bold")
        )
        self.amount_entry.pack(fill="x", padx=22)

        self.apply_button = ctk.CTkButton(
            self.input_card,
            text="APPLY POINTS",
            command=self.start_apply,
            height=46,
            corner_radius=14,
            fg_color=self.BLUE,
            hover_color=self.BLUE_HOVER,
            text_color=self.WHITE,
            font=ctk.CTkFont("Segoe UI", 12, "bold")
        )
        self.apply_button.pack(fill="x", padx=22, pady=(13, 20))

        self.progress = ctk.CTkProgressBar(
            self.content,
            height=8,
            corner_radius=4,
            fg_color="#451416",
            progress_color=self.BLUE,
            mode="indeterminate"
        )
        self.progress.set(0)
        self.progress.pack(fill="x", pady=(0, 10))

        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ctk.CTkLabel(
            self.content,
            textvariable=self.status_var,
            text_color=self.MUTED,
            font=ctk.CTkFont("Segoe UI", 11, "bold")
        )
        self.status_label.pack(pady=(0, 10))

        self.console_button = ctk.CTkButton(
            self.content,
            text="HIDE CONSOLE",
            command=self.toggle_console,
            height=36,
            corner_radius=12,
            fg_color="#541719",
            hover_color="#702024",
            text_color=self.WHITE,
            font=ctk.CTkFont("Segoe UI", 10, "bold")
        )
        self.console_button.pack(fill="x", pady=(0, 10))

        self.console_frame = ctk.CTkFrame(
            self.content,
            corner_radius=16,
            fg_color=self.INPUT,
            border_width=0
        )
        self.console_frame.pack(fill="both", expand=True)

        self.output = tk.Text(
            self.console_frame,
            height=8,
            font=("Consolas", 9),
            bg=self.INPUT,
            fg=self.INPUT_TEXT,
            insertbackground=self.INPUT_TEXT,
            selectbackground="#AB2528",
            relief="flat",
            bd=0,
            padx=14,
            pady=12,
            wrap="word",
            state="disabled"
        )
        self.output.pack(fill="both", expand=True, padx=5, pady=5)
        self.output.tag_configure("center", justify="center")

        self.root.bind("<Return>", lambda event: self.start_apply())
        self.root.bind("<Configure>", self._schedule_gradient)
        self.amount_entry.focus_set()
        self.root.after(10, self._draw_gradient)
        self.root.after(100, self.process_messages)
        self.root.after(150, self.start_version_check)

    def show_help(self):
        messagebox.showinfo(
            "How to Use",
            "1. Start Bodycam and remain at the main menu.\n\n"
            "2. Check the dot beside R-POINTS TOOL:\n"
            "   • Green — the game version is compatible.\n"
            "   • Red — the game version is not compatible.\n"
            "   • Gray — Bodycam is not running.\n\n"
            "3. Enter the number of R-Points you want to add. "
            f"The allowed range is 1 to {MAX_QA_AMOUNT:,}.\n\n"
            "4. Click APPLY POINTS and wait for the success message.\n\n"
            "Do not close Bodycam or this tool while the operation is running. "
            "Avoid exceeding 40,000 total R-Points in the game."
        )

    def _help_enter(self, _event=None):
        self.background.itemconfigure(
            self.help_circle,
            fill=self.BLUE_HOVER
        )
        self.background.configure(cursor="hand2")

    def _help_leave(self, _event=None):
        self.background.itemconfigure(
            self.help_circle,
            fill=self.BLUE
        )
        self.background.configure(cursor="")

    def start_version_check(self):
        """Check the executable hash off the GUI thread."""
        if self._version_check_running:
            return

        self._version_check_running = True
        threading.Thread(
            target=self._version_worker,
            daemon=True
        ).start()

    def _version_worker(self):
        state, detail = check_game_version()
        self.message_queue.put(("version_status", (state, detail)))

    def _update_version_badge(self, state, detail):
        colors = {
            "correct": self.SUCCESS,
            "incorrect": self.ERROR,
            "error": self.ERROR,
            "not_running": self.MUTED,
        }
        self.version_dot.configure(text_color=colors.get(state, self.MUTED))
        self.version_dot.configure(cursor="hand2")
        self.badge_text.configure(cursor="hand2")
        self.version_dot.bind(
            "<Button-1>",
            lambda _event, message=detail: messagebox.showinfo(
                "Game Version", message
            )
        )
        self.badge_text.bind(
            "<Button-1>",
            lambda _event, message=detail: messagebox.showinfo(
                "Game Version", message
            )
        )

    @staticmethod
    def _mix(base, glow, strength):
        return tuple(
            int(base[i] + (glow[i] - base[i]) * strength)
            for i in range(3)
        )

    def _schedule_gradient(self, _event=None):
        if self._gradient_job is not None:
            self.root.after_cancel(self._gradient_job)
        self._gradient_job = self.root.after(80, self._draw_gradient)

    def _draw_gradient(self):
        self._gradient_job = None
        width = max(self.root.winfo_width(), 620)
        height = max(self.root.winfo_height(), 410)
        sample_w = max(160, width // 3)
        sample_h = max(110, height // 3)
        pixels = []
        glows = (
            (-0.05, 0.06, 0.90, (171, 37, 40), 0.60),
            (1.03, 0.90, 0.72, (130, 24, 28), 0.58),
            (0.55, 0.40, 1.05, (75, 15, 17), 0.28),
        )

        for y in range(sample_h):
            ny = y / max(sample_h - 1, 1)
            for x in range(sample_w):
                nx = x / max(sample_w - 1, 1)
                color = self.BASE
                for gx, gy, radius, glow, power in glows:
                    distance = ((nx - gx) ** 2 + (ny - gy) ** 2) ** 0.5
                    strength = max(0.0, 1.0 - distance / radius) ** 2 * power
                    color = self._mix(color, glow, strength)
                pixels.append(color)

        image = Image.new("RGB", (sample_w, sample_h))
        image.putdata(pixels)
        image = image.resize((width, height), Image.Resampling.LANCZOS)
        draw = ImageDraw.Draw(image)
        card_width = 610
        card_height = 560
        left = (width - card_width) // 2
        top = (height - card_height) // 2
        draw.rounded_rectangle(
            (
                left,
                top,
                left + card_width - 1,
                top + card_height - 1
            ),
            radius=28,
            fill=self.CARD,
            outline=self.CARD_BORDER,
            width=1
        )

        self._gradient_photo = ImageTk.PhotoImage(image)
        self.background.itemconfigure(
            self.background_image,
            image=self._gradient_photo
        )
        self.background.coords(self.content_window, width // 2, height // 2)

    def toggle_console(self):
        if self.console_visible:
            self.console_frame.pack_forget()
            self.console_button.configure(text="SHOW CONSOLE")
            self.console_visible = False
        else:
            self.console_frame.pack(fill="both", expand=True)
            self.console_button.configure(text="HIDE CONSOLE")
            self.console_visible = True

    def log(self, text):
        self.output.configure(state="normal")
        self.output.insert("end", text + "\n", "center")
        self.output.see("end")
        self.output.configure(state="disabled")

    def clear_output(self):
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")

    def start_apply(self):
        try:
            amount = int(self.amount_var.get().replace(",", "").strip())
        except ValueError:
            messagebox.showerror("Invalid Amount", "Enter a whole number.")
            return

        if not 1 <= amount <= MAX_QA_AMOUNT:
            messagebox.showerror(
                "Invalid Amount",
                f"Points must be between 1 and {MAX_QA_AMOUNT:,}."
            )
            return

        self.clear_output()
        self.log(f"Requested points: {amount:,}")
        self.apply_button.configure(state="disabled")
        self.amount_entry.configure(state="disabled")
        self.status_label.configure(text_color=self.MUTED)
        self.progress.start()
        self.status_var.set("Starting...")
        threading.Thread(
            target=self.worker,
            args=(amount,),
            daemon=True
        ).start()

    def process_messages(self):
        try:
            while True:
                msg_type, data = self.message_queue.get_nowait()

                if msg_type == "status":
                    self.status_var.set(data)
                    self.log(data)

                elif msg_type == "version_status":
                    self._version_check_running = False
                    state, detail = data
                    self._update_version_badge(state, detail)
                    self.root.after(5000, self.start_version_check)

                elif msg_type == "success":
                    self.finish()
                    self.status_var.set("Completed successfully")
                    self.status_label.configure(text_color=self.SUCCESS)
                    self.log("\nSUCCESS")
                    self.log(json.dumps(data, ensure_ascii=False, indent=2))

                    requested = data.get("requestedAmount")
                    final_read = data.get("finalRead")
                    final_value = (
                        final_read.get("value")
                        if isinstance(final_read, dict)
                        else None
                    )
                    message = "Operation completed successfully."
                    if requested is not None:
                        message += f"\n\nRequested amount: {requested:,}"
                    if final_value is not None:
                        message += f"\nFinal balance: {final_value:,}"
                    messagebox.showinfo("Success", message)

                elif msg_type == "error":
                    self.finish()
                    self.status_var.set("Error")
                    self.status_label.configure(text_color=self.ERROR)
                    self.log("\nERROR")
                    self.log(data)
                    messagebox.showerror("Error", data)

        except queue.Empty:
            pass

        self.root.after(100, self.process_messages)

    def finish(self):
        self.progress.stop()
        self.progress.set(0)
        self.apply_button.configure(state="normal")
        self.amount_entry.configure(state="normal")

def main():

    root = ctk.CTk()

    app = PointsGUI(
        root
    )

    root.mainloop()


if __name__ == "__main__":
    main()
