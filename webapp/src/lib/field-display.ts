// Stored field labels are free text, so they are normalized before they are
// matched: case, diacritics and separators are dropped and the label is
// looked up as a whole phrase.
export type FieldKind =
  | 'email' | 'phone' | 'username' | 'fullName' | 'firstName' | 'lastName' | 'birthDate'
  | 'address' | 'city' | 'country' | 'postalCode' | 'company' | 'nationalId' | 'idIssueDate'
  | 'taxCode' | 'socialInsurance' | 'healthInsurance' | 'hometown' | 'permanentAddress'
  | 'placeOfBirth' | 'server' | 'port' | 'database' | 'path' | 'website' | 'oneTimeCode' | 'other';

export interface FieldPresentation {
  kind: FieldKind;
  labelKey: string | null;
  secret: boolean;
  noise: boolean;
}

export type NoteBlock =
  | { kind: 'text'; text: string }
  | { kind: 'recoveryCodes'; codes: string[] }
  | { kind: 'pem'; text: string }
  | { kind: 'pairs'; pairs: Array<{ label: string; value: string; secret: boolean }> };

// Every label that belongs to a kind, written the way it looks after
// normalization.
const LABELS_BY_KIND: Record<FieldKind, string[]> = {
  email: ['email', 'e mail', 'mail', 'email address', 'dia chi email'],
  phone: ['phone', 'phone number', 'mobile', 'sdt', 'so dien thoai', 'dien thoai'],
  username: ['username', 'user name', 'user', 'ten tai khoan', 'login', 'account'],
  fullName: ['full name', 'ho ten', 'ho va ten', 'display name'],
  firstName: ['first name', 'given name', 'ten'],
  lastName: ['last name', 'family name', 'surname', 'ho'],
  birthDate: ['dob', 'date of birth', 'birthday', 'ngay sinh'],
  address: ['address', 'dia chi'],
  city: ['city', 'thanh pho'],
  country: ['country', 'quoc gia'],
  postalCode: ['zip', 'zipcode', 'zip code', 'postal code', 'zip postal code'],
  company: ['company', 'company name', 'cong ty'],
  nationalId: ['cccd', 'cmnd', 'can cuoc', 'national id', 'id number'],
  idIssueDate: ['ngay cap', 'ngay cap cccd', 'ngap cap', 'issued on', 'issue date'],
  taxCode: ['ma so thue', 'mst', 'tax code', 'tax id'],
  socialInsurance: ['ma so bhxh', 'bhxh'],
  healthInsurance: ['bao hiem y te', 'bhyt'],
  hometown: ['nguyen quan', 'que quan'],
  permanentAddress: ['thuong tru', 'dia chi thuong tru'],
  placeOfBirth: ['noi sinh', 'place of birth'],
  server: ['server', 'host', 'hostname', 'endpoint'],
  port: ['port'],
  database: ['database', 'db'],
  path: ['path'],
  website: ['website', 'url', 'link', 'site'],
  oneTimeCode: ['one time code', 'otp', 'ma xac nhan'],
  other: [],
};

const KIND_BY_LABEL: Record<string, FieldKind> = {};
for (const [kind, labels] of Object.entries(LABELS_BY_KIND) as Array<[FieldKind, string[]]>) {
  for (const label of labels) KIND_BY_LABEL[label] = kind;
}

// A label that carries one of these words holds a secret even when it is
// stored as plain text.
const SECRET_LABEL_RE =
  /(^| )(key|secret|token|password|passwd|pass|pin|private|private ket|api key|access key|client secret|security answer|seed|mnemonic|recovery|mat khau)( |$)/;

// Labels left over from an autofilled form.
const NOISE_LABEL_RE =
  /(remember|rememberme|keep me signed in|agree|terms|code box input|ghi nho|duy tri dang nhap|^in$|^field name$|^bef data$)/;

const EMAIL_VALUE_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_VALUE_RE = /^\+?[\d\s().-]{7,}$/;

const PEM_RE = /-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----/;
const RECOVERY_CODE_RE = /^[A-Za-z0-9-]{6,16}$/;
const PAIR_RE = /^([^:]{1,40}):\s*(.+)$/;

export function normalizeLabel(label: string): string {
  return String(label ?? '')
    .toLowerCase()
    .replace(/đ/g, 'd')
    .normalize('NFD')
    .replace(/\p{M}/gu, '')
    .replace(/[\s_\-.\[\](){}]+/g, ' ')
    .trim();
}

export function presentField(label: string, storedType: number): FieldPresentation {
  const normalized = normalizeLabel(label);
  const kind = KIND_BY_LABEL[normalized] ?? 'other';
  const type = Number(storedType) || 0;
  // A boolean field holds a flag and never a secret, a hidden field always
  // holds one, and a plain text field is masked when its label looks secret.
  const secret = type !== 2 && (type === 1 || (kind !== 'oneTimeCode' && SECRET_LABEL_RE.test(normalized)));

  return {
    kind,
    labelKey: kind === 'other' ? null : `txt_field_kind_${kind}`,
    secret,
    noise: NOISE_LABEL_RE.test(normalized),
  };
}

export function usernameKind(value: string): 'email' | 'phone' | 'username' {
  const text = String(value ?? '').trim();
  if (EMAIL_VALUE_RE.test(text)) return 'email';
  if (PHONE_VALUE_RE.test(text) && (text.match(/\d/g)?.length ?? 0) >= 7) return 'phone';
  return 'username';
}

export function parseNote(note: string): NoteBlock[] {
  const source = String(note ?? '');
  if (!source.trim()) return [];

  const lines = source.split('\n').filter((line) => line.trim());
  const codeLines = lines.filter((line) => RECOVERY_CODE_RE.test(line.trim()));
  const pairLines = lines.filter((line) => PAIR_RE.test(line));
  // Codes are often written one per line with a blank line between them, so a
  // note that is nothing but codes is recognized before it is split up.
  if (!PEM_RE.test(source) && pairLines.length < 2 && lines.length >= 4 && codeLines.length === lines.length) {
    return [{ kind: 'recoveryCodes', codes: codeLines.map((line) => line.trim()) }];
  }

  const blocks: NoteBlock[] = [];
  for (const paragraph of source.split(/\n\s*\n/)) {
    if (!paragraph.trim()) continue;

    const pem = PEM_RE.exec(paragraph);
    if (pem) {
      pushText(blocks, paragraph.slice(0, pem.index));
      blocks.push({ kind: 'pem', text: pem[0] });
      pushText(blocks, paragraph.slice(pem.index + pem[0].length));
      continue;
    }

    const paragraphLines = paragraph.split('\n').filter((line) => line.trim());
    const codes = paragraphLines.filter((line) => RECOVERY_CODE_RE.test(line.trim()));
    if (paragraphLines.length >= 4 && codes.length * 5 >= paragraphLines.length * 4) {
      pushRuns(blocks, paragraphLines, (line) => RECOVERY_CODE_RE.test(line.trim()), (run) => ({
        kind: 'recoveryCodes',
        codes: run.map((line) => line.trim()),
      }));
      continue;
    }

    const pairs = paragraphLines.filter((line) => PAIR_RE.test(line));
    if (pairs.length >= 2) {
      pushRuns(blocks, paragraphLines, (line) => PAIR_RE.test(line), (run) => ({ kind: 'pairs', pairs: run.map(toPair) }));
      continue;
    }

    pushText(blocks, paragraphLines.join('\n'));
  }

  return mergeText(blocks);
}

function toPair(line: string): { label: string; value: string; secret: boolean } {
  const match = PAIR_RE.exec(line);
  const label = (match?.[1] ?? '').trim();
  const value = (match?.[2] ?? '').trim();
  return { label, value, secret: presentField(label, 0).secret };
}

// Keeps the order of the lines: a run of matching lines becomes one block and
// a run of other lines becomes one text block.
function pushRuns(
  blocks: NoteBlock[],
  lines: string[],
  matches: (line: string) => boolean,
  toBlock: (run: string[]) => NoteBlock,
): void {
  let run: string[] = [];
  let matched = matches(lines[0] ?? '');
  const flush = () => {
    if (!run.length) return;
    if (matched) blocks.push(toBlock(run));
    else pushText(blocks, run.join('\n'));
    run = [];
  };

  for (const line of lines) {
    const lineMatched = matches(line);
    if (lineMatched !== matched) {
      flush();
      matched = lineMatched;
    }
    run.push(line);
  }
  flush();
}

function pushText(blocks: NoteBlock[], text: string): void {
  const trimmed = text.trim();
  if (trimmed) blocks.push({ kind: 'text', text: trimmed });
}

function mergeText(blocks: NoteBlock[]): NoteBlock[] {
  const merged: NoteBlock[] = [];
  for (const block of blocks) {
    const previous = merged[merged.length - 1];
    if (block.kind === 'text' && previous?.kind === 'text') {
      merged[merged.length - 1] = { kind: 'text', text: `${previous.text}\n\n${block.text}` };
    } else {
      merged.push(block);
    }
  }
  return merged;
}
