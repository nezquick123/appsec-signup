from io import BytesIO
import os
from flask import Blueprint, render_template, request, flash, redirect, send_file, url_for, current_app, abort
from ..models import UserRole, db, Post, Comment, User
from ..utils.security import token_required, get_logged_in_user
from ..utils.file_handler import save_picture

content_bp = Blueprint('content', __name__)

@content_bp.route('/gallery')
def gallery():
    """Public gallery viewable by anyone."""
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('q', '') # Get search query
    query = Post.query

    if search_query:
        # Filter by title containing the search query (case-insensitive)
        query = query.filter(Post.title.ilike(f'%{search_query}%'))

    # Get posts ordered by newest first
    posts = query.order_by(Post.created_at.desc()).paginate(page=page, per_page=9)
    
    # Pass search_query to the template to preserve input value
    return render_template('gallery.html', posts=posts, search_query=search_query)

@content_bp.route('/post/<post_id>')
def post_detail(post_id):
    """Public post detail view."""
    post = db.session.get(Post, post_id)
    if not post:
        abort(404)
        
    current_user = get_logged_in_user()

    # Pass current_user to the template
    return render_template('post_detail.html', post=post, current_user=current_user, role = True if current_user and User.query.filter_by(username=current_user).first().role  in [UserRole.OWNER, UserRole.ADMIN] else False)

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
                file_data = file.read()
                
                post = Post(
                    title=title,
                    content=file_data,
                    author_username=request.username,
                    description=description
                )
                
                db.session.add(post)
                db.session.commit()
                
                flash('Image uploaded successfully!', 'success')
                return redirect(url_for('content.gallery'))
                
            except Exception as e:
                db.session.rollback()
                flash(f'Error uploading file: {str(e)}', 'error')
                
    return render_template('upload.html')

@content_bp.route('/post/image/<post_id>')
def serve_image(post_id):
    post = Post.query.get_or_404(post_id)
    
    if not post.content:
        abort(404)

    # Convert binary data to a file-like object
    return send_file(
        BytesIO(post.content),
        mimetype='image/jpeg',  # Defaults to jpeg, browsers usually auto-detect if it's png
        as_attachment=False,
        download_name=f"{post.title}.jpg"
    )

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