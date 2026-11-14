// Pure model of the answer buttons: each button carries the exact `answer` command built from
// the peek response that rendered it, so a tap can never borrow the `menu_id` of a later peek.
import { MAX_ANSWER_N, type Cmd, type MenuOption, type Peek } from "../protocol/messages";

export type ChoiceNote = "input" | "range";

export interface Choice {
  option: MenuOption;
  /** Why the desktop cannot take this answer remotely, else null. */
  note: ChoiceNote | null;
  disabled: boolean;
  /** Present for answerable options only. */
  cmd: Cmd | null;
}

export function menuChoices(paneId: string, peek: Peek | null, canRespond: boolean, busy: boolean): Choice[] {
  if (!peek) return [];
  return peek.menu.map((option) => {
    const note: ChoiceNote | null = option.input ? "input" : option.n < 1 || option.n > MAX_ANSWER_N ? "range" : null;
    const answerable = note === null && peek.menuId !== "";
    return {
      option,
      note,
      disabled: !canRespond || busy || !answerable,
      cmd: answerable
        ? { op: "answer", pane: paneId, n: option.n, label: option.label, menu_id: peek.menuId }
        : null,
    };
  });
}
