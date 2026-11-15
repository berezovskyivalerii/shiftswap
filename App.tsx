import React, { useState } from 'react';
import { Button, ScrollView, Text, TextInput, View } from 'react-native';

type Role = 'employee' | 'manager';

interface RegisteredUser {
  fullName: string;
  email: string;
  role: Role;
  passwordSalt: string;
  passwordHash: string;
  // Employee fields
  specialty?: string;
  branchCode?: string;
  // Manager fields (branch configuration)
  branchName?: string;
  branchAddress?: string;
  branchHours?: string;
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

function hashPasswordWithSalt(password: string, salt: string): string {
  const utf8Password = unescape(encodeURIComponent(`${salt}:${password}`));
  return `sha256$${salt}$${sha256(utf8Password)}`;
}

const SPECIALTIES = ['Barista', 'Waiter', 'Courier', 'Cashier', 'Cook'];

export default function App() {
  const [registeredUser, setRegisteredUser] = useState<RegisteredUser | null>(
    null
  );

  // Common fields
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [role, setRole] = useState<Role>('employee');

  // Employee fields
  const [specialty, setSpecialty] = useState('');
  const [branchCode, setBranchCode] = useState('');

  // Manager fields (branch setup)
  const [branchName, setBranchName] = useState('');
  const [branchAddress, setBranchAddress] = useState('');
  const [branchHours, setBranchHours] = useState('');

  // Validation errors
  const [errors, setErrors] = useState<string[]>([]);

  const validateAndSubmit = () => {
    const validationErrors: string[] = [];

    // 1. Full Name validation (at least first and last name)
    const nameParts = fullName.trim().split(/\s+/).filter(Boolean);
    if (nameParts.length < 2) {
      validationErrors.push(
        'Please enter your full name (at least first and last name).'
      );
    }

    // 2. Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email.trim())) {
      validationErrors.push('Please enter a valid email address.');
    }

    // 3. Password validation
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

    // 4. Role-specific validation
    if (role === 'employee') {
      if (!specialty) {
        validationErrors.push('Please select an employee specialty.');
      }
      if (branchCode.trim().length < 3) {
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

    // Salted password hashing
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
        branchCode: branchCode.trim().toUpperCase(),
        createdAt: new Date().toISOString(),
      });
    } else {
      setRegisteredUser({
        fullName: fullName.trim(),
        email: email.trim().toLowerCase(),
        role: 'manager',
        passwordSalt: salt,
        passwordHash,
        branchName: branchName.trim(),
        branchAddress: branchAddress.trim(),
        branchHours: branchHours.trim(),
        createdAt: new Date().toISOString(),
      });
    }
  };

  const handleReset = () => {
    setRegisteredUser(null);
    setPassword('');
    setConfirmPassword('');
    setErrors([]);
  };

  if (registeredUser) {
    return (
      <ScrollView style={{ padding: 16, marginTop: 24 }}>
        <Text>You are registered with the following data:</Text>
        <Text> </Text>
        <Text>Full Name: {registeredUser.fullName}</Text>
        <Text>Email: {registeredUser.email}</Text>
        <Text>
          Role: {registeredUser.role === 'manager' ? 'Manager' : 'Employee'}
        </Text>

        {registeredUser.role === 'employee' ? (
          <View>
            <Text>Specialty: {registeredUser.specialty}</Text>
            <Text>Branch Code: {registeredUser.branchCode}</Text>
          </View>
        ) : (
          <View>
            <Text>Branch Name: {registeredUser.branchName}</Text>
            <Text>Branch Address: {registeredUser.branchAddress}</Text>
            <Text>Branch Working Hours: {registeredUser.branchHours}</Text>
          </View>
        )}

        <Text>Password Salt: {registeredUser.passwordSalt}</Text>
        <Text>Password Hash: {registeredUser.passwordHash}</Text>
        <Text>Registered At: {registeredUser.createdAt}</Text>
        <Text> </Text>
        <Button title="Back to Registration" onPress={handleReset} />
      </ScrollView>
    );
  }

  return (
    <ScrollView style={{ padding: 16, marginTop: 24 }}>
      <Text>ShiftSwap Registration</Text>
      <Text> </Text>

      <Text>Select Role:</Text>
      <Text>Current Role: {role === 'employee' ? 'Employee' : 'Manager'}</Text>
      <Button
        title="Select: Employee"
        onPress={() => {
          setRole('employee');
          setErrors([]);
        }}
      />
      <Button
        title="Select: Manager"
        onPress={() => {
          setRole('manager');
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
            value={branchCode}
            onChangeText={setBranchCode}
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
