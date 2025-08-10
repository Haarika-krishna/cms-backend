const mongoose = require('mongoose');

const PageSchema = new mongoose.Schema({
  title: { type: String, required: true },
  slug: { type: String, required: true, unique: true },
  data: { type: Object, required: true },
  published: { type: Boolean, default: false },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // new field
}, { timestamps: true });

module.exports = mongoose.model('Page', PageSchema);
