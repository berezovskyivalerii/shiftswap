import React, { useState } from 'react';
import { Button, ScrollView, Text, TextInput, View } from 'react-native';

type Role = 'manager' | 'employee';
type ApprovalMode = 'manual' | 'auto';

interface RegisteredUser {
  fullName: string;
  email: string;
  role: Role;
  passwordSalt: string;
  passwordHash: string;
  specialty?: string;
  branchCode: string;
  branchName?: string;
  branchAddress?: string;
  branchHours?: string;
  createdAt: string;
}

interface ShiftSlot {
  id: string;
  date: string; // YYYY-MM-DD
  startTime: string;
  endTime: string;
  requiredSpecialty: string;
  status: 'UNASSIGNED';
  createdAt: string;
}

// Pure SHA-256 implementation for salted password hashing
function sha256(ascii: string): string {
  const rightRotate = (value: number, amount: number) =>
    (value >>> amount) | (value << (32 - amount));

  const mathPow = Math.pow;
  const maxWord = mathPow(2, 32);
  let result = '';

  const words: number[] = [];
  const asciiBitLength = ascii.length * 8;

  let hash: number[] = [];
  const k: number[] = [];
  let primeCounter = 0;

  const isComposite: Record<number, number> = {};
  for (let candidate = 2; primeCounter < 64; candidate++) {
    if (!isComposite[candidate]) {
      for (let i = 0; i < 313; i += candidate) {
        isComposite[i] = candidate;
      }
      hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
      k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
    }
  }

  ascii += '\x80';
  while ((ascii.length % 64) - 56) ascii += '\x00';
  for (let i = 0; i < ascii.length; i++) {
    const j = ascii.charCodeAt(i);
    words[i >> 2] |= j << (((3 - i) % 4) * 8);
  }
  words[words.length] = (asciiBitLength / maxWord) | 0;
  words[words.length] = asciiBitLength;

  for (let j = 0; j < words.length; ) {
    const w = words.slice(j, (j += 16));
    const oldHash = hash.slice(0);

    for (let i = 0; i < 64; i++) {
      const w15 = w[i - 15];
      const w2 = w[i - 2];

      const a = hash[0];
      const e = hash[4];
      const temp1 =
        hash[7] +
        (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) +
        ((e & hash[5]) ^ (~e & hash[6])) +
        k[i] +
        (w[i] =
          i < 16
            ? w[i]
            : (w[i - 16] +
                (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3)) +
                w[i - 7] +
                (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))) |
              0);

      const temp2 =
        (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) +
        ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));

      hash = [(temp1 + temp2) | 0].concat(hash);
      hash[4] = (hash[4] + temp1) | 0;
      hash.pop();
    }

    for (let i = 0; i < 8; i++) {
      hash[i] = (hash[i] + oldHash[i]) | 0;
    }
  }

  for (let i = 0; i < 8; i++) {
    for (let j = 3; j + 1; j--) {
      const b = (hash[i] >> (j * 8)) & 255;
      result += (b < 16 ? 0 : '') + b.toString(16);
    }
  }
  return result;
}

function generateSalt(): string {
  return Math.random().toString(36).substring(2, 10);
}

function generateBranchInviteCode(): string {
  const randomDigits = Math.floor(1000 + Math.random() * 9000);
  return `BR-${randomDigits}`;
}

function hashPasswordWithSalt(password: string, salt: string): string {
  const utf8Password = unescape(encodeURIComponent(`${salt}:${password}`));
  return `sha256$${salt}$${sha256(utf8Password)}`;
}

function formatDateYMD(year: number, monthIndex: number, day: number): string {
  const mm = String(monthIndex + 1).padStart(2, '0');
  const dd = String(day).padStart(2, '0');
  return `${year}-${mm}-${dd}`;
}

function buildCalendarWeeks(
  year: number,
  monthIndex: number
): Array<Array<number | null>> {
  const daysInMonth = new Date(year, monthIndex + 1, 0).getDate();
  // Convert Sunday=0..Saturday=6 into Monday=0..Sunday=6
  const firstDayJs = new Date(year, monthIndex, 1).getDay();
  const firstDayMondayIndex = (firstDayJs + 6) % 7;

  const weeks: Array<Array<number | null>> = [];
  let currentWeek: Array<number | null> = [];

  for (let i = 0; i < firstDayMondayIndex; i++) {
    currentWeek.push(null);
  }

  for (let day = 1; day <= daysInMonth; day++) {
    currentWeek.push(day);
    if (currentWeek.length === 7) {
      weeks.push(currentWeek);
      currentWeek = [];
    }
  }

  if (currentWeek.length > 0) {
    while (currentWeek.length < 7) {
      currentWeek.push(null);
    }
    weeks.push(currentWeek);
  }

  return weeks;
}

const MONTH_NAMES = [
  'January',
  'February',
  'March',
  'April',
  'May',
  'June',
  'July',
  'August',
  'September',
  'October',
  'November',
  'December',
];

const WEEK_DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
const SPECIALTIES = ['Barista', 'Waiter', 'Courier', 'Cashier', 'Cook'];

export default function App() {
  const now = new Date();
  const initialDateStr = formatDateYMD(
    now.getFullYear(),
    now.getMonth(),
    now.getDate()
  );

  const [registeredUser, setRegisteredUser] = useState<RegisteredUser | null>(
    null
  );

  // Registration form state
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [role, setRole] = useState<Role>('manager');

  // Employee registration fields
  const [specialty, setSpecialty] = useState('');
  const [branchCodeInput, setBranchCodeInput] = useState('');

  // Manager registration fields (branch setup)
  const [branchName, setBranchName] = useState('');
  const [branchAddress, setBranchAddress] = useState('');
  const [branchHours, setBranchHours] = useState('');

  // Validation errors for registration
  const [errors, setErrors] = useState<string[]>([]);

  // ================= MANAGER DASHBOARD STATE (NO MOCKS) =================
  // Block 1: Branch & Invite Management
  const [editBranchName, setEditBranchName] = useState('');
  const [editBranchAddress, setEditBranchAddress] = useState('');
  const [editBranchHours, setEditBranchHours] = useState('');
  const [activeBranchCode, setActiveBranchCode] = useState('');
  const [branchStatusMsg, setBranchStatusMsg] = useState('');

  // Block 2: Swap Rules & Labor Limits
  const [approvalMode, setApprovalMode] = useState<ApprovalMode>('manual');
  const [maxWeeklyHours, setMaxWeeklyHours] = useState('40');
  const [approvalTimeoutHours, setApprovalTimeoutHours] = useState('4');
  const [savedRulesSummary, setSavedRulesSummary] = useState(
    'Mode: Manual Approval | Max Weekly Hours: 40 | Timeout: 4h before shift'
  );
  const [rulesStatusMsg, setRulesStatusMsg] = useState('');

  // Block 3: Interactive Calendar & Shift Slots (starts empty, no mocks)
  const [calendarYear, setCalendarYear] = useState<number>(now.getFullYear());
  const [calendarMonth, setCalendarMonth] = useState<number>(now.getMonth());
  const [selectedCalendarDate, setSelectedCalendarDate] =
    useState<string>(initialDateStr);

  const [shiftSlots, setShiftSlots] = useState<ShiftSlot[]>([]);
  const [slotDate, setSlotDate] = useState<string>(initialDateStr);
  const [slotStartTime, setSlotStartTime] = useState('');
  const [slotEndTime, setSlotEndTime] = useState('');
  const [slotSpecialty, setSlotSpecialty] = useState('');
  const [slotError, setSlotError] = useState('');

  // Block 4 & 5: Real lists for employees and swap requests (strictly empty, no mocks)
  const registeredEmployeesCount = 0;
  const incomingSwapRequestsCount = 0;

  const validateAndSubmit = () => {
    const validationErrors: string[] = [];

    const nameParts = fullName.trim().split(/\s+/).filter(Boolean);
    if (nameParts.length < 2) {
      validationErrors.push(
        'Please enter your full name (at least first and last name).'
      );
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email.trim())) {
      validationErrors.push('Please enter a valid email address.');
    }

    if (password.length < 8) {
      validationErrors.push('Password must be at least 8 characters long.');
    }
    if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
      validationErrors.push(
        'Password must contain at least one letter and one number.'
      );
    }
    if (password !== confirmPassword) {
      validationErrors.push('Passwords do not match.');
    }

    if (role === 'employee') {
      if (!specialty) {
        validationErrors.push('Please select an employee specialty.');
      }
      if (branchCodeInput.trim().length < 3) {
        validationErrors.push(
          'Please enter a branch code (at least 3 characters).'
        );
      }
    } else {
      if (branchName.trim().length < 3) {
        validationErrors.push('Please enter a branch name.');
      }
      if (branchAddress.trim().length < 5) {
        validationErrors.push('Please enter a branch address.');
      }
      if (branchHours.trim().length < 5) {
        validationErrors.push('Please enter branch working hours.');
      }
    }

    if (validationErrors.length > 0) {
      setErrors(validationErrors);
      return;
    }

    setErrors([]);

    const salt = generateSalt();
    const passwordHash = hashPasswordWithSalt(password, salt);

    if (role === 'employee') {
      setRegisteredUser({
        fullName: fullName.trim(),
        email: email.trim().toLowerCase(),
        role: 'employee',
        passwordSalt: salt,
        passwordHash,
        specialty,
        branchCode: branchCodeInput.trim().toUpperCase(),
        createdAt: new Date().toISOString(),
      });
    } else {
      const generatedCode = generateBranchInviteCode();
      const trimmedBranchName = branchName.trim();
      const trimmedBranchAddress = branchAddress.trim();
      const trimmedBranchHours = branchHours.trim();

      setEditBranchName(trimmedBranchName);
      setEditBranchAddress(trimmedBranchAddress);
      setEditBranchHours(trimmedBranchHours);
      setActiveBranchCode(generatedCode);
      setBranchStatusMsg('');
      setRulesStatusMsg('');
      setShiftSlots([]);

      setRegisteredUser({
        fullName: fullName.trim(),
        email: email.trim().toLowerCase(),
        role: 'manager',
        passwordSalt: salt,
        passwordHash,
        branchCode: generatedCode,
        branchName: trimmedBranchName,
        branchAddress: trimmedBranchAddress,
        branchHours: trimmedBranchHours,
        createdAt: new Date().toISOString(),
      });
    }
  };

  // Block 1 handlers
  const handleSaveBranchSettings = () => {
    if (
      editBranchName.trim().length < 3 ||
      editBranchAddress.trim().length < 5 ||
      editBranchHours.trim().length < 5
    ) {
      setBranchStatusMsg(
        'Error: Branch Name (min 3), Address (min 5), and Working Hours (min 5) are required.'
      );
      return;
    }
    if (!registeredUser) return;
    setRegisteredUser({
      ...registeredUser,
      branchName: editBranchName.trim(),
      branchAddress: editBranchAddress.trim(),
      branchHours: editBranchHours.trim(),
    });
    setBranchStatusMsg('Branch settings updated.');
  };

  const handleRegenerateBranchCode = () => {
    const newCode = generateBranchInviteCode();
    setActiveBranchCode(newCode);
    if (registeredUser) {
      setRegisteredUser({
        ...registeredUser,
        branchCode: newCode,
      });
    }
    setBranchStatusMsg(`New branch invite code generated: ${newCode}`);
  };

  // Block 2 handlers
  const handleSaveRules = () => {
    const hoursNum = Number(maxWeeklyHours);
    const timeoutNum = Number(approvalTimeoutHours);
    if (
      !Number.isFinite(hoursNum) ||
      hoursNum <= 0 ||
      hoursNum > 168 ||
      !Number.isFinite(timeoutNum) ||
      timeoutNum < 0
    ) {
      setRulesStatusMsg(
        'Error: Please enter valid numbers for Max Weekly Hours (1-168) and Approval Timeout (>= 0).'
      );
      return;
    }
    const modeLabel =
      approvalMode === 'manual' ? 'Manual Approval' : 'Auto-Approval';
    setSavedRulesSummary(
      `Mode: ${modeLabel} | Max Weekly Hours: ${hoursNum} | Timeout: ${timeoutNum}h before shift`
    );
    setRulesStatusMsg('Swap rules and labor limits saved.');
  };

  // Calendar navigation handlers
  const handlePrevMonth = () => {
    if (calendarMonth === 0) {
      setCalendarYear((y) => y - 1);
      setCalendarMonth(11);
    } else {
      setCalendarMonth((m) => m - 1);
    }
  };

  const handleNextMonth = () => {
    if (calendarMonth === 11) {
      setCalendarYear((y) => y + 1);
      setCalendarMonth(0);
    } else {
      setCalendarMonth((m) => m + 1);
    }
  };

  const handleSelectDay = (day: number) => {
    const ymd = formatDateYMD(calendarYear, calendarMonth, day);
    setSelectedCalendarDate(ymd);
    setSlotDate(ymd);
  };

  // Block 3 handlers
  const handleCreateShiftSlot = () => {
    if (!slotDate.trim()) {
      setSlotError('Please enter or select a shift date (YYYY-MM-DD).');
      return;
    }
    if (!slotStartTime.trim() || !slotEndTime.trim()) {
      setSlotError('Please enter both start time and end time.');
      return;
    }
    if (!slotSpecialty) {
      setSlotError('Please select a required specialty for the shift.');
      return;
    }

    setSlotError('');
    const newSlot: ShiftSlot = {
      id: `SLOT-${Date.now()}`,
      date: slotDate.trim(),
      startTime: slotStartTime.trim(),
      endTime: slotEndTime.trim(),
      requiredSpecialty: slotSpecialty,
      status: 'UNASSIGNED',
      createdAt: new Date().toISOString(),
    };

    setShiftSlots((prev) => [...prev, newSlot]);
    setSelectedCalendarDate(slotDate.trim());
    setSlotStartTime('');
    setSlotEndTime('');
  };

  const handleDeleteShiftSlot = (slotId: string) => {
    setShiftSlots((prev) => prev.filter((s) => s.id !== slotId));
  };

  const handleLogout = () => {
    setRegisteredUser(null);
    setPassword('');
    setConfirmPassword('');
    setErrors([]);
  };

  // ================= POST-REGISTRATION VIEWS =================
  if (registeredUser) {
    if (registeredUser.role === 'employee') {
      return (
        <ScrollView style={{ padding: 16, marginTop: 24 }}>
          <Text>You are registered as Employee (Manager-only panel mode):</Text>
          <Text> </Text>
          <Text>Full Name: {registeredUser.fullName}</Text>
          <Text>Email: {registeredUser.email}</Text>
          <Text>Role: Employee</Text>
          <Text>Specialty: {registeredUser.specialty}</Text>
          <Text>Branch Code: {registeredUser.branchCode}</Text>
          <Text>Password Salt: {registeredUser.passwordSalt}</Text>
          <Text>Password Hash: {registeredUser.passwordHash}</Text>
          <Text>Registered At: {registeredUser.createdAt}</Text>
          <Text> </Text>
          <Button title="Logout / Back to Registration" onPress={handleLogout} />
        </ScrollView>
      );
    }

    const calendarWeeks = buildCalendarWeeks(calendarYear, calendarMonth);
    const slotsForSelectedDate = shiftSlots.filter(
      (s) => s.date === selectedCalendarDate
    );

    // ================= FULL MANAGER FUNCTIONALITY (NO STYLES, NO MOCKS) =================
    return (
      <ScrollView style={{ padding: 16, marginTop: 24 }}>
        <Text>MANAGER CONTROL PANEL</Text>
        <Text>You are registered with the following data:</Text>
        <Text>Full Name: {registeredUser.fullName}</Text>
        <Text>Email: {registeredUser.email}</Text>
        <Text>Role: Manager</Text>
        <Text>Password Salt: {registeredUser.passwordSalt}</Text>
        <Text>Password Hash: {registeredUser.passwordHash}</Text>
        <Text>Registered At: {registeredUser.createdAt}</Text>

        <Text> </Text>
        <Text>--------------------------------------------------</Text>
        <Text>1. BRANCH & INVITE MANAGEMENT</Text>
        <Text>Current Branch Invite Code for Staff: {activeBranchCode}</Text>
        <Button
          title="Regenerate Branch Code"
          onPress={handleRegenerateBranchCode}
        />

        <Text>Branch Name:</Text>
        <TextInput
          style={{ borderWidth: 1, padding: 4 }}
          value={editBranchName}
          onChangeText={setEditBranchName}
        />

        <Text>Branch Address:</Text>
        <TextInput
          style={{ borderWidth: 1, padding: 4 }}
          value={editBranchAddress}
          onChangeText={setEditBranchAddress}
        />

        <Text>Branch Working Hours:</Text>
        <TextInput
          style={{ borderWidth: 1, padding: 4 }}
          value={editBranchHours}
          onChangeText={setEditBranchHours}
        />

        <Button
          title="Save Branch Settings"
          onPress={handleSaveBranchSettings}
        />
        {branchStatusMsg !== '' && <Text>{branchStatusMsg}</Text>}

        <Text> </Text>
        <Text>--------------------------------------------------</Text>
        <Text>2. SWAP RULES & LABOR LIMITS</Text>
        <Text>Active Rules: {savedRulesSummary}</Text>
        <Text>
          Selected Approval Mode:{' '}
          {approvalMode === 'manual' ? 'Manual Approval' : 'Auto-Approval'}
        </Text>
        <Button
          title="Set Mode: Manual Approval"
          onPress={() => setApprovalMode('manual')}
        />
        <Button
          title="Set Mode: Auto-Approval"
          onPress={() => setApprovalMode('auto')}
        />

        <Text>Max Weekly Hours per Employee:</Text>
        <TextInput
          style={{ borderWidth: 1, padding: 4 }}
          keyboardType="numeric"
          value={maxWeeklyHours}
          onChangeText={setMaxWeeklyHours}
        />

        <Text>Approval Timeout (hours before shift start):</Text>
        <TextInput
          style={{ borderWidth: 1, padding: 4 }}
          keyboardType="numeric"
          value={approvalTimeoutHours}
          onChangeText={setApprovalTimeoutHours}
        />

        <Button title="Save Rules" onPress={handleSaveRules} />
        {rulesStatusMsg !== '' && <Text>{rulesStatusMsg}</Text>}

        <Text> </Text>
        <Text>--------------------------------------------------</Text>
        <Text>3. BRANCH SHIFT CALENDAR & SLOTS</Text>
        <Text>
          Calendar Month: {MONTH_NAMES[calendarMonth]} {calendarYear}
        </Text>
        <View style={{ flexDirection: 'row' }}>
          <Button title="Prev Month" onPress={handlePrevMonth} />
          <Button title="Next Month" onPress={handleNextMonth} />
        </View>

        <Text> </Text>
        <Text>
          Click a day to view or add shift slots (number in brackets = shift
          slots count):
        </Text>

        {/* Weekday Headers */}
        <View style={{ flexDirection: 'row' }}>
          {WEEK_DAYS.map((dayName) => (
            <View
              key={dayName}
              style={{ flex: 1, borderWidth: 1, padding: 4 }}
            >
              <Text>{dayName}</Text>
            </View>
          ))}
        </View>

        {/* Calendar Grid Rows */}
        {calendarWeeks.map((week, weekIdx) => (
          <View key={weekIdx} style={{ flexDirection: 'row' }}>
            {week.map((dayNum, dayIdx) => {
              if (dayNum === null) {
                return (
                  <View
                    key={`empty-${dayIdx}`}
                    style={{ flex: 1, borderWidth: 1, padding: 4 }}
                  >
                    <Text>-</Text>
                  </View>
                );
              }

              const dateStr = formatDateYMD(calendarYear, calendarMonth, dayNum);
              const countForDay = shiftSlots.filter(
                (s) => s.date === dateStr
              ).length;
              const isSelected = selectedCalendarDate === dateStr;
              const label = isSelected
                ? `*${dayNum}* [${countForDay}]`
                : `${dayNum} [${countForDay}]`;

              return (
                <View
                  key={dateStr}
                  style={{ flex: 1, borderWidth: 1, padding: 2 }}
                >
                  <Button
                    title={label}
                    onPress={() => handleSelectDay(dayNum)}
                  />
                </View>
              );
            })}
          </View>
        ))}

        <Text> </Text>
        <Text>Selected Calendar Date: {selectedCalendarDate}</Text>
        <Text>
          Shift Slots on {selectedCalendarDate} ({slotsForSelectedDate.length}):
        </Text>
        {slotsForSelectedDate.length === 0 ? (
          <Text>No shift slots scheduled for {selectedCalendarDate}.</Text>
        ) : (
          slotsForSelectedDate.map((slot) => (
            <View key={slot.id}>
              <Text>
                [{slot.id}] {slot.date} | {slot.startTime} - {slot.endTime} |
                Specialty: {slot.requiredSpecialty} | Status: {slot.status}
              </Text>
              <Button
                title="Assign Employee (Requires registered employees)"
                onPress={() => {}}
                disabled={registeredEmployeesCount === 0}
              />
              <Button
                title="Publish to Open Market / Push to Staff (Requires registered employees)"
                onPress={() => {}}
                disabled={registeredEmployeesCount === 0}
              />
              <Button
                title="Delete Shift Slot"
                onPress={() => handleDeleteShiftSlot(slot.id)}
              />
              <Text> </Text>
            </View>
          ))
        )}

        <Text> </Text>
        <Text>Create New Shift Slot:</Text>
        <Text>Date (YYYY-MM-DD):</Text>
        <TextInput
          style={{ borderWidth: 1, padding: 4 }}
          value={slotDate}
          onChangeText={setSlotDate}
        />

        <Text>Start Time (HH:MM):</Text>
        <TextInput
          style={{ borderWidth: 1, padding: 4 }}
          value={slotStartTime}
          onChangeText={setSlotStartTime}
        />

        <Text>End Time (HH:MM):</Text>
        <TextInput
          style={{ borderWidth: 1, padding: 4 }}
          value={slotEndTime}
          onChangeText={setSlotEndTime}
        />

        <Text>Required Specialty: {slotSpecialty || 'None'}</Text>
        {SPECIALTIES.map((spec) => (
          <Button
            key={spec}
            title={`Select Specialty: ${spec}`}
            onPress={() => setSlotSpecialty(spec)}
          />
        ))}

        {slotError !== '' && <Text>Error: {slotError}</Text>}
        <Button title="Create Shift Slot" onPress={handleCreateShiftSlot} />

        <Text> </Text>
        <Text>All Created Shift Slots in Branch ({shiftSlots.length}):</Text>
        {shiftSlots.length === 0 ? (
          <Text>No shift slots created yet.</Text>
        ) : (
          shiftSlots.map((slot) => (
            <Text key={slot.id}>
              - {slot.date} ({slot.startTime} - {slot.endTime}) |{' '}
              {slot.requiredSpecialty} | {slot.status}
            </Text>
          ))
        )}

        <Text> </Text>
        <Text>--------------------------------------------------</Text>
        <Text>4. INCOMING SWAP REQUESTS</Text>
        <Text>
          Active Swap Requests: {incomingSwapRequestsCount} (No employees
          registered in branch)
        </Text>
        <Button
          title="Approve Selected Swap"
          onPress={() => {}}
          disabled={incomingSwapRequestsCount === 0}
        />
        <Button
          title="Reject Selected Swap"
          onPress={() => {}}
          disabled={incomingSwapRequestsCount === 0}
        />
        <Button
          title="Force Cancel / Return Shift to Original Owner"
          onPress={() => {}}
          disabled={incomingSwapRequestsCount === 0}
        />

        <Text> </Text>
        <Text>--------------------------------------------------</Text>
        <Text>5. BRANCH STAFF & ROSTER</Text>
        <Text>
          Connected Employees: {registeredEmployeesCount} (0 employees joined
          with code {activeBranchCode})
        </Text>
        <Button
          title="Verify / Approve New Employee"
          onPress={() => {}}
          disabled={registeredEmployeesCount === 0}
        />
        <Button
          title="Change Employee Specialty"
          onPress={() => {}}
          disabled={registeredEmployeesCount === 0}
        />
        <Button
          title="Remove Employee from Branch"
          onPress={() => {}}
          disabled={registeredEmployeesCount === 0}
        />
        <Button
          title="Export Monthly Timesheet"
          onPress={() => {}}
          disabled={registeredEmployeesCount === 0}
        />

        <Text> </Text>
        <Text>--------------------------------------------------</Text>
        <Text>6. ACCOUNT & SESSION</Text>
        <Button title="Logout / Back to Registration" onPress={handleLogout} />
        <Text> </Text>
      </ScrollView>
    );
  }

  // ================= REGISTRATION SCREEN =================
  return (
    <ScrollView style={{ padding: 16, marginTop: 24 }}>
      <Text>ShiftSwap Registration</Text>
      <Text> </Text>

      <Text>Select Role:</Text>
      <Text>Current Role: {role === 'manager' ? 'Manager' : 'Employee'}</Text>
      <Button
        title="Select: Manager"
        onPress={() => {
          setRole('manager');
          setErrors([]);
        }}
      />
      <Button
        title="Select: Employee"
        onPress={() => {
          setRole('employee');
          setErrors([]);
        }}
      />

      <Text> </Text>
      <Text>Full Name:</Text>
      <TextInput
        style={{ borderWidth: 1, padding: 4 }}
        value={fullName}
        onChangeText={setFullName}
      />

      <Text>Email:</Text>
      <TextInput
        style={{ borderWidth: 1, padding: 4 }}
        keyboardType="email-address"
        autoCapitalize="none"
        value={email}
        onChangeText={setEmail}
      />

      <Text>Password (min 8 chars, letters and numbers):</Text>
      <TextInput
        style={{ borderWidth: 1, padding: 4 }}
        secureTextEntry
        value={password}
        onChangeText={setPassword}
      />

      <Text>Confirm Password:</Text>
      <TextInput
        style={{ borderWidth: 1, padding: 4 }}
        secureTextEntry
        value={confirmPassword}
        onChangeText={setConfirmPassword}
      />

      <Text> </Text>
      {role === 'employee' ? (
        <View>
          <Text>Employee Settings — Select Specialty:</Text>
          <Text>Selected Specialty: {specialty || 'None'}</Text>
          {SPECIALTIES.map((spec) => (
            <Button
              key={spec}
              title={`Specialty: ${spec}`}
              onPress={() => setSpecialty(spec)}
            />
          ))}

          <Text>Branch Code:</Text>
          <TextInput
            style={{ borderWidth: 1, padding: 4 }}
            value={branchCodeInput}
            onChangeText={setBranchCodeInput}
          />
        </View>
      ) : (
        <View>
          <Text>Manager Settings — Branch Setup:</Text>
          <Text>Branch Name:</Text>
          <TextInput
            style={{ borderWidth: 1, padding: 4 }}
            value={branchName}
            onChangeText={setBranchName}
          />

          <Text>Branch Address:</Text>
          <TextInput
            style={{ borderWidth: 1, padding: 4 }}
            value={branchAddress}
            onChangeText={setBranchAddress}
          />

          <Text>Branch Working Hours:</Text>
          <TextInput
            style={{ borderWidth: 1, padding: 4 }}
            value={branchHours}
            onChangeText={setBranchHours}
          />
        </View>
      )}

      <Text> </Text>
      {errors.length > 0 && (
        <View>
          <Text>Validation Errors:</Text>
          {errors.map((err, index) => (
            <Text key={index}>- {err}</Text>
          ))}
          <Text> </Text>
        </View>
      )}

      <Button title="Register" onPress={validateAndSubmit} />
    </ScrollView>
  );
}
