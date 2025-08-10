const express = require('express');
const Page = require('../models/Page');
const { authMiddleware, adminMiddleware } = require('../middleware/auth');

const router = express.Router();

// ADMIN: Get all pages
router.get('/', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const pages = await Page.find().populate('user', 'name email');
    res.json(pages);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching pages' });
  }
});

// USER: Get my pages only
router.get('/mine', authMiddleware, async (req, res) => {
  try {
    const pages = await Page.find({ user: req.user._id });
    res.json(pages);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching my pages' });
  }
});

// CREATE a page
router.post('/', authMiddleware, async (req, res) => {
  try {
    const { title, slug, data, published } = req.body;
    const newPage = new Page({
      title,
      slug,
      data,
      published: published || false,
      user: req.user._id
    });
    const savedPage = await newPage.save();
    res.status(201).json(savedPage);
  } catch (error) {
    res.status(500).json({ message: 'Error creating page' });
  }
});

// UPDATE a page
router.put('/:id', authMiddleware, async (req, res) => {
  try {
    const updatedPage = await Page.findOneAndUpdate(
      { _id: req.params.id, user: req.user._id }, // ensures only owner can update
      req.body,
      { new: true }
    );
    if (!updatedPage) return res.status(404).json({ message: 'Page not found or not yours' });
    res.json(updatedPage);
  } catch (error) {
    res.status(500).json({ message: 'Error updating page' });
  }
});

module.exports = router;
