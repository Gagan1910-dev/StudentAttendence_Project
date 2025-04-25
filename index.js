import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// Mock database
const users = [
  {
    id: '1',
    name: 'John Doe',
    email: 'teacher@example.com',
    password: '$2a$10$XH9CdcQZkV/Tpr0SFnNR5eGQPQeARSgF9G4cOsXz4hoZkVnJM6Uaa', // 'password'
    role: 'teacher',
  },
  {
    id: '2',
    name: 'Jane Smith',
    email: 'student@example.com',
    password: '$2a$10$XH9CdcQZkV/Tpr0SFnNR5eGQPQeARSgF9G4cOsXz4hoZkVnJM6Uaa', // 'password'
    role: 'student',
  }
];

const classes = [
  {
    id: '1',
    name: 'Mathematics 101',
    schedule: 'MWF 9:00 AM - 10:30 AM',
    teacherId: '1',
    students: ['2']
  },
  {
    id: '2',
    name: 'Physics 201',
    schedule: 'TTh 11:00 AM - 12:30 PM',
    teacherId: '1',
    students: ['2']
  }
];

const attendance = [
  {
    id: '1',
    classId: '1',
    date: '2025-04-01',
    records: [
      { studentId: '2', status: 'present' }
    ]
  },
  {
    id: '2',
    classId: '1',
    date: '2025-04-03',
    records: [
      { studentId: '2', status: 'absent' }
    ]
  }
];

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'snaptrack-secret-key';

// Auth Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ message: 'Unauthorized' });
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Forbidden' });
    req.user = user;
    next();
  });
};

// Routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = users.find(u => u.email === email);
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    
    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1d' });
    
    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get classes for teacher
app.get('/api/classes/teacher', authenticateToken, (req, res) => {
  if (req.user.role !== 'teacher') {
    return res.status(403).json({ message: 'Forbidden' });
  }
  
  const teacherClasses = classes.filter(cls => cls.teacherId === req.user.id);
  res.json(teacherClasses);
});

// Get classes for student
app.get('/api/classes/student', authenticateToken, (req, res) => {
  if (req.user.role !== 'student') {
    return res.status(403).json({ message: 'Forbidden' });
  }
  
  const studentClasses = classes.filter(cls => cls.students.includes(req.user.id));
  res.json(studentClasses);
});

// Mark attendance
app.post('/api/attendance', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'teacher') {
      return res.status(403).json({ message: 'Only teachers can mark attendance' });
    }
    
    const { classId, date, records } = req.body;
    
    // Check if the class exists and belongs to the teacher
    const classExists = classes.find(cls => cls.id === classId && cls.teacherId === req.user.id);
    if (!classExists) {
      return res.status(404).json({ message: 'Class not found or not authorized' });
    }
    
    // Check if attendance already exists for this date and class
    const existingAttendance = attendance.find(a => a.classId === classId && a.date === date);
    
    if (existingAttendance) {
      // Update existing attendance
      existingAttendance.records = records;
      res.json(existingAttendance);
    } else {
      // Create new attendance record
      const newAttendance = {
        id: (attendance.length + 1).toString(),
        classId,
        date,
        records
      };
      
      attendance.push(newAttendance);
      res.status(201).json(newAttendance);
    }
  } catch (error) {
    console.error('Attendance error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get attendance for a specific class
app.get('/api/attendance/:classId', authenticateToken, (req, res) => {
  try {
    const { classId } = req.params;
    
    // Check if the user has access to this class
    if (req.user.role === 'teacher') {
      const hasAccess = classes.some(cls => cls.id === classId && cls.teacherId === req.user.id);
      if (!hasAccess) {
        return res.status(403).json({ message: 'Not authorized to view this class' });
      }
    } else {
      const hasAccess = classes.some(cls => cls.id === classId && cls.students.includes(req.user.id));
      if (!hasAccess) {
        return res.status(403).json({ message: 'Not enrolled in this class' });
      }
    }
    
    const classAttendance = attendance.filter(a => a.classId === classId);
    res.json(classAttendance);
  } catch (error) {
    console.error('Get attendance error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});