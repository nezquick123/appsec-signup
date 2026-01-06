import os
from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app, abort
from ..models import UserRole, db, Post, Comment, User
from ..utils.security import token_required, get_logged_in_user, get_role
from ..utils.file_handler import save_picture

content_bp = Blueprint('content', __name__)

@content_bp.route('/gallery')
def gallery():
    """Public gallery viewable by anyone."""
    page = request.args.get('page', 1, type=int)
    # Get posts ordered by newest first
    posts = Post.query.order_by(Post.created_at.desc()).paginate(page=page, per_page=9)
    return render_template('gallery.html', posts=posts)

@content_bp.route('/post/<post_id>')
def post_detail(post_id):
    """Public post detail view."""
    post = db.session.get(Post, post_id)
    if not post:
        abort(404)
        
    current_user = get_logged_in_user()
    role = get_role()
    
    # Pass current_user to the template
    return render_template('post_detail.html', post=post, current_user=current_user, role = True if current_user and (role == 'OWNER' or role == 'ADMIN') else False)

@content_bp.route('/upload', methods=['GET', 'POST'])
@token_required
def upload():
    """Secure upload for logged-in users."""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
            
        file = request.files['file']
        title = request.form.get('title')
        description = request.form.get('description')

        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)

        if file:
            try:
                filename = save_picture(file)
                post = Post(
                    title=title,
                    filename=filename,
                    author_username=request.username,
                    description=description
                )
                db.session.add(post)
                db.session.commit()
                flash('Image uploaded successfully!', 'success')
                return redirect(url_for('content.gallery'))
            except ValueError as e:
                flash(str(e), 'error')
                
    return render_template('upload.html')

@content_bp.route('/post/<post_id>/delete', methods=['POST'])
@token_required
def delete_post(post_id):
    post = db.session.get(Post, post_id)
    if not post:
        abort(404)
        
    # Authorization: Only owner can delete or role 'ADMIN', 'OWNER'
    if post.author_username != request.username and User.query.filter_by(username=request.username).first().role not in [UserRole.OWNER, UserRole.ADMIN]:
        flash("You are not authorized to delete this post.", "error")
        return redirect(url_for('content.post_detail', post_id=post.id))

    try:
        # Remove file from disk
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], post.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            
        db.session.delete(post)
        db.session.commit()
        flash('Post deleted.', 'success')
    except Exception as e:
        flash('Error deleting post.', 'error')
        
    return redirect(url_for('content.gallery'))

@content_bp.route('/post/<post_id>/comment', methods=['POST'])
@token_required
def add_comment(post_id):
    content = request.form.get('content')
    if not content:
        flash('Comment cannot be empty', 'error')
        return redirect(url_for('content.post_detail', post_id=post_id))

    comment = Comment(
        content=content,
        post_id=post_id,
        author_username=request.username
    )
    db.session.add(comment)
    db.session.commit()
    flash('Comment added!', 'success')
    return redirect(url_for('content.post_detail', post_id=post_id))

@content_bp.route('/post/<post_id>/comment/<comment_id>/delete', methods=['POST'])
@token_required
def delete_comment(post_id, comment_id):
    comment = db.session.get(Comment, comment_id)
    if not comment:
        abort(404)
        
    # Authorization: Only comment author or role 'ADMIN', 'OWNER' can delete
    if comment.author_username != request.username and User.query.filter_by(username=request.username).first().role not in [UserRole.OWNER, UserRole.ADMIN]:
        flash("You are not authorized to delete this comment.", "error")
        return redirect(url_for('content.post_detail', post_id=post_id))

    try:
        db.session.delete(comment)
        db.session.commit()
        flash('Comment deleted.', 'success')
    except Exception as e:
        flash('Error deleting comment.', 'error')
        
    return redirect(url_for('content.post_detail', post_id=post_id))